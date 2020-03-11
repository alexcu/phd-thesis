# frozen_string_literal: true

# Author::    Alex Cummaudo  (mailto:ca@deakin.edu.au)
# Copyright:: Copyright (c) 2019 Alex Cummaudo
# License::   MIT License

require 'sinatra'
require 'time'
require 'json'
require 'cgi'
require 'require_all'
require_all 'lib'


set :root, File.dirname(__FILE__)
set :public_folder, File.join(File.dirname(__FILE__), 'static')
set :show_exceptions, false
set :demo_folder, File.join(File.dirname(__FILE__), 'demo')

store = {}

before do
  if request.body.size.positive?
    request.body.rewind
    @params = JSON.parse(request.body.read, symbolize_names: true)
  end
end

def halt!(code, message)
  content_type 'text/plain'
  halt code, message
end

def check_brc_id(id, store)
  halt! 400, 'Benchmark id must be a positive integer' unless id.integer? && id.to_i.positive?
  halt! 400, "No such benchmark request client exists with id=#{id}" unless store.key?(id)
end

get '/' do
  File.read(File.expand_path('index.html', settings.public_folder))
end

# Creates a new benchmark request client with given parameters
post '/benchmark' do
  # Extract params
  service = params[:service] || ''
  benchmark_dataset = params[:benchmark_dataset] || ''
  max_labels = params[:max_labels] || ''
  min_confidence = params[:min_confidence] || ''
  trigger_on_schedule = params[:trigger_on_schedule] || ''
  trigger_on_failcount = params[:trigger_on_failcount] || ''
  benchmark_callback_uri = params[:benchmark_callback_uri] || ''
  warning_callback_uri = params[:warning_callback_uri] || ''
  expected_labels = params[:expected_labels] || ''
  delta_labels = params[:delta_labels] || ''
  delta_confidence = params[:delta_confidence] || ''
  severity = params[:severity] || ''

  # Check param types
  unless max_labels.integer? && max_labels.to_i.positive?
    halt! 400, 'max_labels must be a positive integer'
  end
  unless min_confidence.float? && min_confidence.to_f.positive?
    halt! 400, 'min_confidence must be a positive float'
  end
  unless delta_labels.integer? && delta_labels.to_i.positive?
    halt! 400, 'delta_labels must be a positive integer'
  end
  unless delta_confidence.float? && delta_confidence.to_f.positive?
    halt! 400, 'delta_confidence must be a positive float'
  end
  unless ICVSB::VALID_SERVICES.include?(service.to_sym)
    halt! 400, "service must be one of #{ICVSB::VALID_SERVICES.join(', ')}"
  end
  unless trigger_on_schedule.cronline?
    halt! 400, 'trigger_on_schedule must be a cron string in * * * * * (see man 5 crontab)'
  end
  unless trigger_on_failcount.integer? && trigger_on_failcount.to_i >= -1
    halt! 400, 'trigger_on_failcount must be zero or positive integer'
  end
  if !benchmark_callback_uri.empty? && !benchmark_callback_uri.uri?
    halt! 400, 'benchmark_callback_uri is not a valid URI'
  end

  unless ICVSB::VALID_SEVERITIES.include?(severity.to_sym)
    halt! 400, "severity must be one of #{ICVSB::VALID_SEVERITIES.join(', ')}"
  end
  if ICVSB::BenchmarkSeverity[name: severity.to_s] == ICVSB::BenchmarkSeverity::WARNING && !warning_callback_uri.uri?
    halt! 400, 'Must provide a valid warning_callback_uri when severity is WARNING'
  end

  halt! 400, 'benchmark_dataset has not been specified' if benchmark_dataset.empty?
  benchmark_dataset = benchmark_dataset.lines.map(&:strip)
  expected_labels = expected_labels.empty? ? [] : expected_labels.split(',').map(&:strip)
  benchmark_dataset.each do |uri|
    unless uri.uri?
      halt! 400, "benchmark_dataset must be a list of uris separated by a newline character; #{uri} is not a valid URI"
    end
  end

  # Convert params
  brc = ICVSB::BenchmarkedRequestClient.new(
    ICVSB::Service[name: service.to_s],
    benchmark_dataset,
    max_labels: max_labels.to_i,
    min_confidence: min_confidence.to_f,
    opts: {
      trigger_on_schedule: trigger_on_schedule,
      trigger_on_failcount: trigger_on_failcount.to_i,
      benchmark_callback_uri: benchmark_callback_uri,
      warning_callback_uri: warning_callback_uri,
      expected_labels: expected_labels,
      delta_labels: delta_labels.to_i,
      delta_confidence: delta_confidence.to_f,
      severity: ICVSB::BenchmarkSeverity[name: severity.to_s],
      autobenchmark: false
    }
  )
  # Benchmark on new thread
  Thread.new do
    brc.trigger_benchmark
    store[brc.object_id] = brc
  end

  store[brc.object_id] = brc

  status 201
  content_type 'application/json;charset=utf-8'
  { id: brc.object_id }.to_json
end

# Gets all auxillary information about the benchmark
get '/benchmark/:id' do
  id = params[:id].to_i
  check_brc_id(id, store)
  brc = store[id]

  content_type 'application/json;charset=utf-8'
  {
    id: id,
    service: brc.service.name,
    created_at: brc.created_at,
    current_key_id: brc.current_key ? brc.current_key.id : nil,
    is_benchmarking: brc.benchmarking?,
    last_scheduled_benchmark_time: brc.last_scheduled_benchmark_time,
    next_scheduled_benchmark_time: brc.next_scheduled_benchmark_time,
    mean_scheduled_benchmark_duration: brc.mean_scheduled_benchmark_duration,
    last_scheduled_benchmark_duration: brc.last_scheduled_benchmark_duration,
    invalid_state_count: brc.invalid_state_count,
    last_benchmark_time: brc.last_benchmark_time,
    benchmark_count: brc.benchmark_count,
    config: {
      max_labels: brc.max_labels,
      min_confidence: brc.min_confidence,
      key: brc.key_config,
      benchmarking: brc.benchmark_config
    },
    benchmark_dataset: brc.dataset
  }.to_json
end

patch '/benchmark/:id' do
  # Set is_benchmarking to true to force the benchmark to reevaluate...
  # Else, endpoint is ignored
  id = params['id'].to_i
  check_brc_id(id, store)
  brc = store[id]

  status 202
  response = {
    id: id,
    service: brc.service.name,
    current_key_id: brc.current_key ? brc.current_key.id : nil,
    is_benchmarking: brc.benchmarking?
  }
  if brc.service == ICVSB::Service::DEMO && params[:demo_timestamp]
    brc.demo_timestamp = params[:demo_timestamp] if ['t1','t2'].include?(params[:demo_timestamp])
    response[:timestamp] = brc.demo_timestamp
  end

  brc.trigger_benchmark if params[:is_benchmarking] && !brc.benchmarking?

  response.to_json
end

# Gets all auxillary information about this key's benchmark
get '/benchmark/:id/key' do
  id = params[:id].to_i
  check_brc_id(id, store)
  brc = store[id]

  halt! 422, 'The requested benchmark client is still benchmarking its first key' if brc.current_key.nil?

  current_key_id = brc.current_key.id
  redirect "/key/#{current_key_id}"
end

get '/key/:id' do
  id = params[:id].to_i
  bk = BenchmarkKey[id: params[:id]]

  halt! 400, 'id must be an integer' unless id.integer?
  halt! 400, "No such benchmark key request client exists with id=#{id}" if bk.nil?

  content_type 'application/json;charset=utf-8'
  {
    id: bk.id,
    service: bk.service.name,
    created_at: bk.created_at,
    benchmark_dataset: bk.batch_request.uris,
    success: bk.success?,
    expired: bk.expired?,
    severity: bk.severity.name,
    responses: bk.batch_request.responses.map(&:hash),
    config: {
      expected_labels: bk.expected_labels_set.to_a,
      delta_labels: bk.delta_labels,
      delta_confidence: bk.delta_confidence,
      max_labels: bk.max_labels,
      min_confidence: bk.min_confidence
    }
  }.to_json
end

# Gets the log of the benchmark with the given id
get '/benchmark/:id/log' do
  id = params[:id].to_i

  check_brc_id(id, store)

  content_type 'text/plain'
  store[id].read_log
end

post '/callbacks/benchmark' do
  "Acknowledged benchmark completion with params: '#{params}'..."
end

post '/callbacks/warning' do
  "Acknowledged benchmark warning params: '#{params}'..."
end

# Labels resources against the provided uri. This is a conditional HTTP request.
# Must provide "If-Match" request header field with at least one ETag. Note that
# the ETag must ALWAYS been provided in the following format:
#
#   W/"<benchmark-id>[;<behaviour-token>]"
#
# Note that the ETag is a weak ETag; ``weak ETag values of two representations
# of the same resources might be semantically equivalent, but not byte-for-byte
# identical.'' (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag).
# That is, as the developer is not directly accessing the service, they are
# only getting a semantically equivalent representation of the labels, but not
# a byte-for-byte equivalent (the model may have changed slightly, given the
# latest benchmark used.)
#
# The first id, the benchmark-id, is mandatory as the request must know what
# benchmark dataset (and service) the requested URI is being made against.
#
# The following behaviour-token is optional, indicating the tolerances to which
# the response will be made, and the behaviour by which the response will change
# given if evolution has occured since the last benchmark was made. (Not that
# internally to this project, we refer to the behaviour token as a BenchmarkKey
# -- see ICVSB::BenchmarkKey.)
#
# One may provide multiple ETags (separated by commas) in the format:
#
#  W/"<benchmark-id1>[;<behaviour-token1>]",W/"<benchmark-id2>[;<behaviour-token2>]" ...
#
# Where this is the case, the label requested will attempt to match ANY of the
# tags provided. If failure occurs for the first, it will default to the next
# ETag, and so on.
#
# If NO behaviour-token is specified, then then (additionally) one must provide
# an "If-Unmodified-Since" request header field, indicating that the resource
# (labels) must have been unmodified since the given date. This will attempt to
# automatically locate the nearest behaviour token that was generated after the
# given date and request the labels against that date.
#
# The endpoint will return one of the following HTTP responses:
#
#   - 200 OK if this is the first request made to this URI;
#   - 400 Bad Request if invalid parameters were provided by the client;
#   - 412 Precondition Failed if the key/unmodified time provided is no longer
#     valid, and thus the key provided (or time provided) is violating the
#     valid tolerances embedded within the key (responding further details
#     reasoning what tolerances were violated as metadata in the response body);
#   - 428 Precondition Required if no If-Match field is provided in request;
#   - 422 Unprocessable Entity if a service error has occured, indicating the
#     service cannot process the entity or a bad request was made.
#   - 500 Internal Server Error if a facade error has occured.
#
# The endpont will return the following HTTP response headers:
#
#   - ETag: The ETag that was used to successfully generate a response
#   - Last-Modified: The last time the benchmark-id was benchmarked against
#       its dataset
#   - Expires: The next time the benchmark with the provided id will be
#       benchmarked against its dataset
#   - Age: Indicates that the repsonse provided is cached (i.e., no changes
#       to the service the last time it was benchmarked against the dataset
#       to not be considered a violation); returns the time elapsed in seconds
#       since then
get '/labels' do
  image_uri = CGI.unescape(params[:image])

  if_match = request.env['HTTP_IF_MATCH'] || ''
  if_unmodified_since = request.env['HTTP_IF_UNMODIFIED_SINCE'] || ''

  halt! 400, 'URI provided to analyse is not a valid URI' unless image_uri.uri?
  halt! 428, 'Missing If-Match in request header' if if_match.nil?
  if !if_unmodified_since.empty? && !if_unmodified_since.httpdate?
    halt! 400, 'If Unmodified Since must be compliant with the RFC 2616 HTTP date format'
  end

  if_unmodified_since_date = if_unmodified_since.empty? ? nil : Time.httpdate(if_unmodified_since)

  relay_body = nil
  relay_etag = nil
  relay_last_modified = nil
  relay_expires = nil

  # Scan through each comma-separated ETag
  etags = if_match.scan(%r{W\/"(\d+;?\d+)",?})
  if etags.empty?
    halt! 428, 'Malformed ETags provided. Ensure you are using the correct format.'
  end
  etags.each do |etag|
    etag = etag[0]
    benchmark_id, benchmark_key_id = etag.split(';').map(&:to_i)

    # Check if we have a valid benchmark id
    check_brc_id(benchmark_id, store)
    brc = store[benchmark_id]
    bk = nil


    # Check if we have a key; if no key we must have a If-Unmodified-Since.
    if benchmark_key_id.nil? && if_unmodified_since.empty?
      halt! 400, "You have provided a benchmark id (id=#{benchmark_id}) "\
                'without a behaviour token. Please provide a behaviour token '\
                'or include the If-Unmodified-Since request header with a RFC '\
                '2616-compliant HTTP date string.'
    elsif !benchmark_key_id.nil?
      # Check if valid key
      if ICVSB::BenchmarkKey.where(id: benchmark_key_id).empty?
        halt! 400, "No such key with id #{benchmark_key_id} exists!"
      end
      unless benchmark_key_id.integer? && benchmark_key_id.positive?
        halt! 400, 'Behaviour token must be a positive integer.'
      end

      bk = ICVSB::BenchmarkKey[id: benchmark_key_id]
    elsif !if_unmodified_since_date.nil?
      bk = brc.find_key_since(if_unmodified_since_date)
      halt! 412, "No compatible behaviour token found unmodified since #{if_unmodified_since_date}." if bk.nil?
    end

    # Process...
    result = brc.send_uri_with_key(image_uri, bk)

    # Set HTTP status+body as appropriate if there is no more ETags or if
    # this was a successful response (i.e., no errors so don't keep trying other
    # ETags...)
    error = result.key?(:key_errors) || result.key?(:response_errors) || result.key?(:service_error)
    if [etag] == etags.last || !error
      if result[:key_errors] || result[:response_errors]
        status 412
        content_type 'application/json;charset=utf-8'

        key_error_len = result[:key_errors].nil? ? 0 : result[:key_errors].length
        res_error_len = result[:response_errors].nil? ? 0 : result[:response_errors].length

        key_error_data = result[:key_errors].nil? ? [] : result[:key_errors].map(&:to_h)
        res_error_data = result[:response_errors].nil? ? [] : result[:response_errors].map(&:to_h)

        relay_body = {
          num_key_errors: key_error_len,
          num_response_errors: res_error_len,
          key_errors: key_error_data,
          response_errors: res_error_data
        }.to_json
      elsif result[:service_error]
        status 422
        content_type 'text/plain'
        relay_body = result[:service_error]
      else
        content_type 'application/json;charset=utf-8'
        unless result[:cached].nil?
          age_sec = ((DateTime.now - result[:cached]) * 24 * 60 * 60).to_i.to_s
          headers 'Age' => age_sec
        end
        status 200
        relay_body = result[:response].to_json
      end
      relay_etag = etag
      relay_last_modified = brc.current_key.nil? ? brc.created_at.httpdate : brc.current_key.created_at.httpdate
      relay_expires = brc.next_scheduled_benchmark_time.httpdate
    end
  end
  headers \
    'ETag' => "W/\"#{relay_etag}\"", \
    'Expires' => relay_expires, \
    'Last-Modified' => relay_last_modified
  body relay_body
end

error do |e|
  halt! 500, e.message
end

###
# DEMONSTRATION RELATED API
###
get '/demo/categories.json' do
  content_type 'application/json;charset=utf-8'
  send_file(File.join(settings.demo_folder, 'categories.json'))
end

get '/demo/random/:type.jpg' do
  category_data = JSON.parse(
    File.read(File.join(settings.demo_folder, 'categories.json'))
  )
  ok_categories = category_data.keys

  category = params[:type]

  halt! 400, 'No category provided' if category.empty?
  unless ok_categories.include?(category)
    halt! 400, "Unknown category '#{category}'. Accepted category types are: '#{ok_categories.join("', '")}'."
  end

  id = category_data[category].sample

  redirect "/demo/data/#{id}.jpg"
end

get '/demo/data/:id.*' do |_, ext|
  image_id = params[:id].split('.').first
  time_id = params[:id].split('.').last

  unless File.exist?(File.join(settings.demo_folder, image_id + '.jpg'))
    halt! 400, "No such image with id '#{image_id}' exists in the demo database."
  end
  unless %w[jpg jpeg json].include?(ext)
    halt! 400, 'Invalid file extension. Suffix with .jp[e]g or .t1.json or .t2.json.'
  end
  ext = 'jpg' if ext == 'jpeg'

  if ext == 'jpg'
    content_type 'image/jpeg'
  else
    content_type 'application/json;charset=utf-8'
    halt! 400, 'Missing time id (.t1 or .t2).' if time_id.empty? || !%w[t1 t2].include?(time_id)
    image_id += '.' + time_id
  end

  send_file(File.join(settings.demo_folder, image_id + '.' + ext))
end
