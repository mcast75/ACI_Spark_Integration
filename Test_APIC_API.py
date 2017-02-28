#!/usr/bin/env python
__author__ = "Michael Castellana"
__email__ = "micastel@cisco.com"
__status__ = "Development"

#import the necessary libraries to make NXAPI REST calls
import requests, json, sys, socket, getpass, time, websocket, thread, ssl, tornado


is_IP = False
time_auth = 0
AUTH_TIMEOUT = 90
auth_cookie = {}

def cookie_good(time_auth, timeout):
	#if the auth-cookie has expired we need to ask for a new one
	if time.time() - time_auth >= timeout:return False
	else: return True 

def get_cookie(ip, user, password):

	url = "http://"+ip+"/api/mo/aaaLogin.json"

	payload = {
	    'aaaUser' : {
	        'attributes' : {
	            'name' : user,
	            'pwd' : password
	            }
	        }
	    }
	auth_cookie = {}

	response = requests.request("POST", url, data=json.dumps(payload))

	if response.status_code == requests.codes.ok:
		data = json.loads(response.text)['imdata'][0]
		token = str(data['aaaLogin']['attributes']['token'])
		auth_cookie = {"APIC-cookie" : token}
		login_time = int(str(data['aaaLogin']['attributes']['firstLoginTime']))


	else:
		print "Authentication ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
		print
		sys.exit(1)
	return login_time, auth_cookie

def post(ip, user, cookie, payload):
	url = "http://"+ip+"/api/node/mo/.json"
	print json.dumps(json.loads(payload))

	try:
		response = requests.request("POST", url, data=json.dumps(json.loads(payload)), cookies=cookie)
		print
		print '\nStatus Code '+ str(response.status_code)
		print 'Success\n\n'
		print json.dumps(json.loads(response.text), indent=2)
		print
		print
	except:
		response = requests.request("POST", url, data=json.dumps(json.loads(payload)), cookies=cookie)
		print "ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
		print
		sys.exit(1)

def get(url, user, cookie):
	try:
		response = requests.request("GET", url, cookies=cookie, verify=False)
		print
		print "GET RESPONSE:"
		print json.dumps(json.loads(response.text), indent=2)
	except:
		response = requests.request("GET", url, cookies=cookie, verify=False)
		print "ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
		sys.exit(1)
		print

def sub(url, user, cookie):
	#try:
	url = url+'?subscription=yes'
	response = requests.request("GET", url, cookies=cookie, verify=False)
	print json.dumps(json.loads(response.text), indent=2)
	print 
	print("\nSubscribed\n")
	#except: 
		#print 'prblem'

def listen(websocket, blank_string):
	while(1):
		result = websocket.recv()
		print 'hit'
		blank_string += blank_string+time.ctime(time.time())+'\n'+json.dumps(json.loads(result), indent=2)+'\n\n'
		f = open('Test_Output','w')
		f.write(blank_string)
		f.close()

def read_file(filepath):

	json_string=''
	try:
		#open the file to be read iteratively and sent to remote device
		file = open(filepath, 'r')
		for line in file.readlines():
			json_string+=str(line)
		file.close
		return json_string
		#To avoid configuration file related errors, close the file.
	except IOErorr:
		print '\n+++ Problem Opening '+config_file+'- No Such File or Directory +++\n'
		sys.exit(1)

if __name__ == '__main__':

	#Disable warnings???
	requests.packages.urllib3.disable_warnings()
	
	print
	ip_addr = "10.122.143.24"
	username = "admin"
	password = "ins3965!"

	print "IP Address: "+ip_addr+"\nUsername: "+username+"\nPassword: "+password+"\n\n"

	time_auth, auth_cookie = get_cookie(ip_addr,username, password)	
		
	while(1):
		#if the auth-cookie has expired we need to ask for a new one
		if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
		host = "http://"+ip_addr+"/socket"+auth_cookie['APIC-cookie']
		ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})

		ws.connect("wss://"+ip_addr+"/socket"+auth_cookie['APIC-cookie'])
		#print ip_addr
		#print auth_cookie["APIC-cookie"]
		#print "ws://"+ip_addr+"/socket"+auth_cookie['APIC-cookie']
		thread.start_new_thread(listen, (ws, ''))
		
		try:
			choice = raw_input("Select 1 to perform GET request or 2 to perform POST request: ")	
			if choice == '1':
				url = read_file("get-url.txt")
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				get(url,'admin', auth_cookie)
				sub_choice = raw_input("\nCreate Subscription for this [y/n]?")
				if sub_choice=='y' or sub_choice=='Y':sub(url, username, auth_cookie)

			
			elif choice == '2':
				payload = read_file("post-json.txt")
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				post(ip_addr,'admin', auth_cookie, payload)
		
		except KeyboardInterrupt :
			print '\nSession Closed\n'
			sys.exit(0)
		






