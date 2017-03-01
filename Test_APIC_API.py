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
	#print "time now: "+str(time.time())+" | time authorized: "+str(time_auth)

	#if the auth-cookie has expired we need to ask for a new one
	if time.time() - time_auth >= timeout:
		#print "***BAD COOKIE***"
		return False
	else: return True 

def get_cookie(ip, user, password):

	#print "******COOKIE GENERATED******"

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
		login_time = time.time()#int(str(data['aaaLogin']['attributes']['firstLoginTime']))
		#print "\n\nAPIC TIME: "+str(login_time)
		#print "MacBook Time: "+str(time.time())

		#print json.dumps(json.loads(response.text), indent=2) 


	else:
		print "Authentication ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
		print
		sys.exit(1)
	return login_time, auth_cookie

def post(ip, user, cookie, payload):
	url = "http://"+ip+"/api/node/mo/.json"

	try:
		response = requests.request("POST", url, data=json.dumps(json.loads(payload)), cookies=cookie)
		print '\tStatus Code: '+ str(response.status_code)
		print '\tSuccess\n\n\n'
		#print json.dumps(json.loads(response.text), indent=2)
		f = open('Post_Output.txt','a')
		f.write(time.ctime(time.time())+'\n'+json.dumps(json.loads(response.text), indent=2)+'\n\n')
		f.close()
	except:
		response = requests.request("POST", url, data=json.dumps(json.loads(payload)), cookies=cookie)
		print "ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
		print
		sys.exit(1)

def get(url, user, cookie):
	#try:
	response = requests.request("GET", url, cookies=cookie, verify=False)
	print '\tStatus Code: '+ str(response.status_code)
	print '\tSuccess\n'
	#f = open('Get_Output.txt','a') - save fort later

	f = open('Get_Output.txt','w') #clean everything up each time
	f.write(time.ctime(time.time())+'\n'+json.dumps(json.loads(response.text), indent=2)+'\n\n')
	f.close()
	# except:
	# 	response = requests.request("GET", url, cookies=cookie, verify=False)
	# 	print "ERROR - "+str(response.status_code)
	# 	print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
	# 	sys.exit(1)
	# 	print

def sub(url, user, cookie):
	try:
		url = url+'?subscription=yes'
		response = requests.request("GET", url, cookies=cookie, verify=False)
		#print json.dumps(json.loads(response.text), indent=2)
		print 
		print("\nSubscribed\n")
	except: 
		print 'prblem'

def listen(websocket, blank_string):
	while(1):
		result = websocket.recv()
		print 'hit'
		blank_string += blank_string+time.ctime(time.time())+'\n'+json.dumps(json.loads(result), indent=2)+'\n\n'
		f = open('Sub_Output.txt','w')
		f.write(blank_string)
		f.close()

def read_file(filepath):

	json_string=''
	try:
		#open the file to be read iteratively and sent to remote device
		file = open(filepath, 'r')
		json_string=file.readline().replace("\n", "")
		print json_string
		#for line in file.readlines():
		#	json_string+=str(line)
		file.close
		return json_string
		#To avoid configuration file related errors, close the file.
	except IOErorr:
		print '\n+++ Problem Opening '+config_file+'- No Such File or Directory +++\n'
		sys.exit(1)

if __name__ == '__main__':
	print '\n\n\n======================================'
	print '|+++\t\t\t          +++|\n|+++      Spark For APIC App      +++|'
	print '|+++\t\t\t          +++|'
	print '======================================\n\n'

	#Disable warnings???
	requests.packages.urllib3.disable_warnings()
	
	print
	ip_addr = "10.122.143.24"
	username = "admin"
	password = "ins3965!"

	print "IP Address: "+ip_addr+"\nUsername: "+username+"\nPassword: "+password+"\n\n"
	#print "****COOKIE 1*****"
	time_auth, auth_cookie = get_cookie(ip_addr,username, password)	

	ws = websocket.WebSocket()#sslopt={"cert_reqs": ssl.CERT_NONE})

	ws.connect("ws://"+ip_addr+"/socket"+auth_cookie['APIC-cookie'])
		#print ip_addr
		#print auth_cookie["APIC-cookie"]
		#print "ws://"+ip_addr+"/socket"+auth_cookie['APIC-cookie']
	thread.start_new_thread(listen, (ws, ''))
		
	while(1):
		#if the auth-cookie has expired we need to ask for a new one
		#print "****COOKIE 2*****"

		if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
		host = "http://"+ip_addr+"/socket"+auth_cookie['APIC-cookie']
		
		
		try:
			choice = raw_input("Select 1 to perform GET request or 2 to perform POST request, 3=Get Tenants&Health, 4=Get Nodes and Health: ")	
			if choice == '1':
				url = read_file("get-url.txt")
				#print "****COOKIE 3*****"

				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				get(url,'admin', auth_cookie)
				sub_choice = raw_input("Create Subscription for this [y/n]? ")
				if sub_choice=='y' or sub_choice=='Y':sub(url, username, auth_cookie)
				print "\n\n"
			
			elif choice == '2':
				payload = read_file("post-json.txt")
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				post(ip_addr,'admin', auth_cookie, payload)

			elif choice == '3':
				url = "https://10.122.143.24/api/class/fvTenant.json?rsp-subtree-include=health,required"
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				get(url,'admin', auth_cookie)
				#sub_choice = raw_input("Create Subscription for this [y/n]? ")
				#if sub_choice=='y' or sub_choice=='Y':sub(url, username, auth_cookie)
				print "\n\n"

			elif choice == '4':
				pod = "pod-1"
				url = "https://10.122.143.24/api/class/topology/"+pod+"/topSystem.json?rsp-subtree-include=health,required"
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: time_auth, auth_cookie = get_cookie(ip_addr,username, password)
				get(url,'admin', auth_cookie)
				#sub_choice = raw_input("Create Subscription for this [y/n]? ")
				#if sub_choice=='y' or sub_choice=='Y':sub(url, username, auth_cookie)
				print "\n\n"

		
		except KeyboardInterrupt :
			print '\n\n\n********************************'
			print '***\t\t\t     ***\n***      Session Closed      ***'
			print '***\t\t\t     ***'
			print '********************************\n\n'

			sys.exit(0)
		






