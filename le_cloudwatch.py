import logging
import json
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
TOKEN = os.environ.get('token') or os.environ.get('LE_LOG_TOKEN')
PREFIX_LINES = os.environ.get('LE_PREFIX_LINES') in ('true', 'yes')
LINE = u'\u2028'.encode('utf-8')


def treat_message(message):
    return message.replace('\n', LINE)


def lambda_handler(event, context):
    sock = create_socket()

    if not validate_uuid(TOKEN):
        logger.critical('{} is not a valid token. Exiting.'.format(TOKEN))
        raise SystemExit

    cw_data = str(event['awslogs']['data'])
    cw_data_decoded = gzip.GzipFile(fileobj=StringIO(cw_data.decode('base64', 'strict'))).read()
    cw_data_dict = json.loads(cw_data_decoded)
    logger.info('Received log stream...')

    prefix = ""
    if PREFIX_LINES:
        # EG cw_data_dict = dict(logGroup="/aws/lambda/hello-world-test",
        #                        logStream="2018/01/04/[$LATEST]bdb3a48bb55c404398b46ef71881d602")
        part1 = cw_data_dict['logGroup'].split('/')[-1]  # only use last part if slash delimited
        part2 = cw_data_dict['logStream'][-7:]  # last 7 significant enough
        prefix = "<" + part1 + " " + part2 + "> "

    # loop through the events and send to Logentries
    send_to_le = lambda line: sock.sendall(
        '%s %s%s\n' % (TOKEN, prefix, treat_message(line))
    )
    for log_event in cw_data_dict['logEvents']:
        # Note that log_event['timestamp'] is not used
        try:
            send_to_le(json.dumps(log_event['extractedFields']))
        except KeyError:
            send_to_le(log_event['message'])

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
