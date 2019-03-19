import logging
import json
import re
import gzip
import socket
import ssl
import certifi
from StringIO import StringIO
import os
from uuid import UUID

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logger.info('Loading function...')

REGION = os.environ.get('region') or 'eu'
ENDPOINT = '{}.data.logs.insight.rapid7.com'.format(REGION)
PORT = 20000
TOKEN = os.environ.get('token')
PREFIX_LINES = os.environ.get('prefix') in ('true', 'yes')
INCLUDE = os.environ.get('include')
LINE_SEPARATOR = u'\u2028'.encode('utf-8')

include_if = None
if INCLUDE:
    include_if = re.compile(INCLUDE)


def treat_message(message):
    return message.strip(' \n').replace('\n', LINE_SEPARATOR)


def send_lines(sock, cw_data_dict):
    # Optionally get a "<functionname stream> " prefix on all lines so can see
    # what logged each line. E.G. extract from cw_data_dict = dict(
    #    logGroup="/aws/lambda/hello-world-test",
    #    logStream="2018/01/04/[$LATEST]bdb3a48bb55c404398b46ef71881d602")
    prefix = ''
    if PREFIX_LINES:
        # only use last part if slash delimited and last 7 significant enough
        prefix = '<%s %s> ' % (
            cw_data_dict['logGroup'].split('/')[-1],
            cw_data_dict['logStream'][-7:]
        )

    def send(logentry):
        sock.sendall('%s %s%s\n' % (
            TOKEN,
            prefix,
            treat_message(logentry))
        )

    # loop through the log events and send to the endpoint
    count = 0
    for log_event in cw_data_dict['logEvents']:
        # Note that log_event['timestamp'] is not used
        extractedFields = log_event.get('extractedFields', None)
        if extractedFields:
            message = json.dumps(extractedFields)
        else:
            message = log_event['message']

        if not include_if or include_if.match(message):
            send(message)
            count += 1

    total = len(cw_data_dict['logEvents'])
    if include_if:
        logger.info('Sent %d/%d log events', count, total)
    else:
        logger.info('Sent %s log events', total)


def lambda_handler(event, context):
    logger.info('Received log stream...')

    if not validate_uuid(TOKEN):
        logger.critical('{} is not a valid token. Exiting.'.format(TOKEN))
        raise SystemExit

    cw_data = str(event['awslogs']['data'])
    cw_data_file = StringIO(cw_data.decode('base64', 'strict'))
    cw_data_json = gzip.GzipFile(fileobj=cw_data_file).read()
    cw_data_dict = json.loads(cw_data_json)

    sock = create_socket()
    send_lines(sock, cw_data_dict)
    sock.close()

    logger.info('Function execution finished.')


def create_socket():
    logger.info('Creating SSL socket')
    s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = ssl.wrap_socket(
        sock=s_,
        keyfile=None,
        certfile=None,
        server_side=False,
        cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=getattr(
            ssl,
            'PROTOCOL_TLSv1_2',
            ssl.PROTOCOL_TLSv1
        ),
        ca_certs=certifi.where(),
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
    )
    try:
        logger.info('Connecting to {}:{}'.format(ENDPOINT, PORT))
        s.connect((ENDPOINT, PORT))
        return s
    except socket.error, exc:
        logger.error('Exception socket.error : {}'.format(exc))


def validate_uuid(uuid_string):
    try:
        val = UUID(uuid_string)
    except Exception as uuid_exc:
        logger.error('Can not validate token: {}'.format(uuid_exc))
        return False
    return val.hex == uuid_string.replace('-', '')
