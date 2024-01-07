#!/bin/bash
export DOCS_KEY
export VENV=$(pwd)/venv

make clean
make clean-docs
make venv
make api
"$VENV"/bin/pip install -e '.[docs]'
cd compiler/docs && "$VENV"/bin/python compiler.py
cd ../..
"$VENV"/bin/sphinx-build -b html "docs/source" "docs/build/html" -j auto
git clone https://eyMarv:"$DOCS_KEY"@github.com/eyMarv/pyrofork-docs.git
cd pyrofork-docs
mkdir -p main
cd main
rm -rf _includes api genindex.html intro py-modindex.html sitemap.xml support.html topics static faq index.html objects.inv searchindex.js start telegram
cp -r ../../docs/build/html/* .
fi
git config --local user.name "eyMarv"
git config --local user.email "eyMarv07@gmail.com"
git add --all
git commit -a -m "docs: $(echo $GITHUB_REF | cut -d '/' -f 3): Update docs $(date '+%Y-%m-%d | %H:%m:%S %p %Z')" --signoff
git push -u origin --all
