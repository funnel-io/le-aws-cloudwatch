.PHONY: certifi zip dist

# get the latest certifi
certifi:
	pip install --upgrade --target .  certifi && rm -rf certifi-2017.4.17.*

# package for upload
zip:
	zip le-aws-cloudwatch-lambda le_config.py le_cloudwatch.py certifi/*

dist: certifi zip