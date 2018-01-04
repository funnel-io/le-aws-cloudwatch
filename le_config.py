import os

# Logentries tokens
# This token is used to associate AWS CloudWatch logs to a log in your Logentries account.
log_token = os.environ['LE_LOG_TOKEN']

# You can supply an optional token to log activity to a log on Logentries and any errors from this script.
# This is optional, it is recommended you use one log file/token for all your Lambda scripts. If you do not
# wish to use this, just leave the value blank.
debug_token = os.environ.get('LE_DEBUG_TOKEN') or ""

# Get a "<functionname stream> " prefix on all log lines so can see which lambda function logged which line
prefix_with_lambda_source = not (
    os.environ.get('LE_PREFIX_WITH_LAMBDA_SOURCE') in ('False', 'false', '0', 'no')
)

# Log to generic activity from this script to our support logging system for Lambda scripts
# this is optional, but helps us improve our service nad can be hand for us helping you debug any issues
# just remove this token if you wish (leave variable in place)
lambda_token = "0ae0162e-855a-4b54-9ae3-bd103006bfc0"

username = os.environ.get('LE_USERNAME') or "username"
