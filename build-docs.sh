#!/bin/bash
export DOCS_KEY
VENV="$(pwd)"/venv
export VENV

branch="main"

make clean
make clean-docs
make venv
make api
"$VENV"/bin/pip install -e '.[docs]'
cd compiler/docs || exit 1 && "$VENV"/bin/python compiler.py
cd  ../.. || exit 1
"$VENV"/bin/sphinx-build -b html "docs/source" "docs/build/html" -j auto
git clone https://eyMarv:"$DOCS_KEY"@github.com/eyMarv/pyroblack-docs.git
cd pyroblack-docs || exit 1
mkdir -p "$branch"
cd "$branch" || exit 1
rm -rf _includes api genindex.html intro py-modindex.html sitemap.xml support.html topics _static faq index.html objects.inv searchindex.js start telegram
cp -r ../../docs/build/html/* .
git config --local user.name "eyMarv"
git config --local user.email "eyMarv07@gmail.com"
git add --all
git commit -a -m "docs: $branch: Update docs $(date '+%Y-%m-%d | %H:%m:%S %p %Z')" --signoff
git push -u origin --all
