#!/usr/bin/env csh

# !!! Ensure \putbib is used where refs should be placed

cat **/*.bib > allrefs.bib

pdflatex thesis

# bibtex bu1.aux, bu2.aux ... buN.aux
foreach auxfile (bu*.aux)
  echo bibtex ‘basename $auxfile .aux‘
  bibtex ‘basename $auxfile .aux‘
end

# need to compile for each buN.aux
foreach auxfile (bu*.aux)
  pdflatex thesis
end


