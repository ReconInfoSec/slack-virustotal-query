import json
import logging
import os
import urllib
import urllib2
import re
from urllib2 import Request, urlopen, URLError, HTTPError
from urlparse import parse_qs

expected_token = os.environ['slack_token']
vt_api = os.environ['vt_api']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def add_field(response,title,value,short=True):
	object = {"title": title,"value": value,"short": short}
	response['attachments'][0]['fields'].append(object)
	return response


def append_response(response,title,value):
	object = {title: value}
	response['attachments'][0][title] = value
	return response


def respond(err,response_url,res=None):
	if not err:
		logger.info("Responding to Slack -- response: %s" % res)
	else:
		logger.info("Slack response error: %s" % err)
	req = Request(response_url, json.dumps(res))
	try:
		makereq = urlopen(req)
		makereq.read()
		logger.info("Responding to Slack -- response: %s" % res)
	except HTTPError as e:
		logger.error("Request failed: %d %s", e.code, e.reason)
	except URLError as e:
		logger.error("Server connection failed: %s", e.reason)
	return


class vtAPI():
	def __init__(self):
		self.api = vt_api
		self.base = 'https://www.virustotal.com/vtapi/v2/'

	def getReport(self,response,md5):
		param = {'resource':md5,'apikey':self.api}
		url = self.base + "file/report"
		data = urllib.urlencode(param)
		result = urllib2.urlopen(url,data)
		jdata =	json.loads(result.read())
		logger.info("VT Report for %s: %s" % (md5,jdata))
		return parse(response,jdata)

	def rescan(self,response,md5):
		param = {'resource':md5,'apikey':self.api}
		url = self.base + "file/rescan"
		data = urllib.urlencode(param)
		result = urllib2.urlopen(url,data)
		message = "\n\tVirus Total Rescan Initiated for -- " + md5 + \
			" (Requery in 10 Mins)"
		return message

	def urlScan(self,response,artifact):
		param = {'resource':artifact,'apikey':self.api}
		url = self.base + "url/report"
		data = urllib.urlencode(param)
		result = urllib2.urlopen(url,data)
		jdata = json.loads(result.read())
		logger.info("VT Report for %s: %s" % (artifact,jdata))
		return urlparse(response,jdata)

vt = vtAPI()


def shared_parse(response,jdata):
	if jdata['response_code'] == 0:
		return respond(None, "Hash Not Found in VT")
		logger.info('Hash not found in VT')

	response = append_response(response,"title_link",jdata['permalink'])

	positives = str(jdata['positives'])
	if jdata['positives'] > 0:
		response = append_response(response,"color","danger")
	else:
		response = append_response(response,"color","good")

	response = add_field(response,"Last Scanned",jdata['scan_date'],True)
	total = str(jdata['total'])
	response = add_field(response,"Positive Detections",positives + "/" + total,True)
	return response


def parse(response,jdata):
	response = shared_parse(response,jdata)
	if jdata['sha256']:
		response = add_field(response,"SHA256",jdata['sha256'],True)
	for vendor in jdata['scans']:
		if jdata['scans'][vendor]['detected']:
			if not jdata['scans'][vendor]['result']:
				jdata['scans'][vendor]['result'] = "Possible Malware"
			vendor_summary = jdata['scans'][vendor]['result'] \
				+ " on " + jdata['scans'][vendor]['update']
			response = add_field(response,vendor,vendor_summary,True)
	return response


def urlparse(response,jdata):
	response = shared_parse(response,jdata)
	for vendor in jdata['scans']:
		if jdata['scans'][vendor]['detected']:
			if not jdata['scans'][vendor]['result']:
				jdata['scans'][vendor]['result'] = "Possibly Malicious Site"
			vendor_summary = "Detected as a " + jdata['scans'][vendor]['result']
			response = add_field(response,vendor,vendor_summary,True)
	return response


def detect_type(artifact):
	if re.findall(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", artifact):
		logger.info("URL Detected")
		return("URL")
	elif re.findall(r"([a-fA-F\d]{32})", artifact):
		logger.info("MD5 Detected")
		return("MD5")
	else:
		logging.warning('Invalid artifact: %s', artifact)


def lambda_handler(event, context):
	logger.info("Event: %s", event)
	body = event['body']
	logger.info("Request body: %s", body)
	params = parse_qs(event['body'])
	token = params['token'][0]
	response_url = params['response_url'][0]

	if token != expected_token:
		logger.error("Request token (%s) does not match expected", token)
		return "Invalid request token"

	response = {
		"response_type": "in_channel",
		#"text": "Message Text (change me)",
		"attachments": [
			{
				"fields": []
			}
		]
	}

	command = params['command'][0]
	logger.info("command: %s", command)

	channel = params['channel_name'][0]
	logger.info("channel: %s", channel)

	command_text = params['text'][0]
	logger.info("command_text: %s", command_text)

	user = params['user_name'][0]
	logger.info("user: %s", user)
	response = append_response(response,"author_name",user)

	activity = "%s results for %s" % (command,command_text)
	response = append_response(response,"title",activity)

	if "virustotal" in command:
		artifact = command_text
		response = add_field(response,"Artifact",artifact,True)
		artifact_type = detect_type(artifact)
		if artifact_type == "URL":
			response = add_field(response,"Artifact Type",artifact_type,True)
			response = vt.urlScan(response,artifact)
			respond(None,response_url, response)
		elif artifact_type == "MD5":
			response = add_field(response,"Artifact Type",artifact_type,True)
			response = vt.getReport(response,artifact)
			respond(None,response_url, response)
		else:
			message = "You did not provide a valid URL \
			or MD5 hash.\nPlease try again in the format `/virustotal \
			http://malware.ru` or \
			`/virustotal 99017f6eebbac24f351415dd410d522d`"
			return message
