.PHONY: certifi zip dist

# get the latest certifi
certifi:
	pip install --upgrade --target .  certifi && rm -rf certifi-201*dist-info

# package for upload
zip:
	zip le-aws-cloudwatch-lambda le_cloudwatch.py certifi/*

dist: certifi zip