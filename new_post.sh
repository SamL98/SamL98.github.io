#!/bin/bash
created_at=$(date "+%Y-%m-%d %H:%M:%S %z")
file_name=_posts/$(date "+%Y-%m-%d")-$1.md

cp template.md $file_name
sed -i "" "s/DATE/${created_at}/" $file_name
