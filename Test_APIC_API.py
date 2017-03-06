#!/usr/bin/env python
__author__ = "Michael Castellana"
__email__ = "micastel@cisco.com"
__status__ = "Development"

#import the necessary libraries to make APIC REST calls
import requests, json, sys, socket, getpass, time, websocket, thread, ssl, tornado


is_IP = False
time_auth = 0
AUTH_TIMEOUT = 90
auth_cookie = {}
subDict={}
tenantHealth={}
flag = "off"
#subMap = {"fvtenant": tenant}

#dont touch this
def cookie_good(time_auth, timeout):
	#print "time now: "+str(time.time())+" | time authorized: "+str(time_auth)

	#if the auth-cookie has expired we need to ask for a new one
	if time.time() - time_auth >= timeout:
		#print "***BAD COOKIE***"
		return False
	else: return True 
#refresh if token times out and resets timer
def refresh_cookie(ip, user, cookie):
	url = "http://"+ip+"/api/aaaRefresh.json"
	get(url, user, cookie)
	return time.time()
#dont touch this- acquires cookie
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
#this works- get request
def get(url, user, cookie):
	try:
		response = requests.request("GET", url, cookies=cookie, verify=False)
		#f = open('Get_Output.txt','a') - save fort later
		f = open('Get_Output.txt','w') #clean everything up each time
		f.write(time.ctime(time.time())+'\n'+json.dumps(json.loads(response.text), indent=2)+'\n\n')
		f.close()
		return response
	except:
		response = requests.request("GET", url, cookies=cookie, verify=False)
		print "ERROR - "+str(response.status_code)
		print str(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])	
		sys.exit(1)
		print
#this works- post request
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
#this works- read input from file
def read_file(filepath):

	json_string=''
	try:
		#open the file to be read iteratively and sent to remote device
		file = open(filepath, 'r')
		#json_string=file.readline().replace("\n", "")
		#print json_string
		for line in file.readlines():
			json_string+=str(line)
		file.close
		return json_string
		#To avoid configuration file related errors, close the file.
	except IOErorr:
		print '\n+++ Problem Opening '+config_file+'- No Such File or Directory +++\n'
		sys.exit(1)

#use this to toggle the fault event
def sabatoge(user, cookie):
	global flag
	if flag=="on":
		url = "https://10.122.143.24/api/node/mo/uni/tn-CSAP_TENANT/ap-App_Prof/epg-EPG-1/rspathAtt-[topology/pod-1/paths-103/pathep-[eth1/45]].json"
		payload = '{"fvRsPathAtt":{"attributes":{"dn":"uni/tn-CSAP_TENANT/ap-App_Prof/epg-EPG-1/rspathAtt-[topology/pod-1/paths-103/pathep-[eth1/45]]","status":"deleted"},"children":[]}}'
		flag = "off"
	
	elif flag == "off":		
		url= "https://10.122.143.24/api/node/mo/uni/tn-CSAP_TENANT/ap-App_Prof/epg-EPG-1.json"
		payload='{"fvRsPathAtt":{"attributes":{"encap":"vlan-1000","tDn":"topology/pod-1/paths-103/pathep-[eth1/45]","status":"created"},"children":[]}}'
		flag="on"

	response = requests.request("POST", url, data=payload, cookies=cookie, verify=False)
	f = open('Get_Output.txt','w') #clean everything up each time
	f.write(time.ctime(time.time())+'\n'+json.dumps(json.loads(response.text), indent=2)+'\n\n')
	f.close()


#creat dictionary of current health scores and subscribe to fault updates
def getTenantHealth(user, cookie):
	url = "https://10.122.143.24/api/class/fvTenant.json?rsp-subtree-include=health"
	response = get(url, user, cookie)
	
	for x in range (0,int(json.loads(response.text)["totalCount"])):
		key = str((json.loads(response.text))["imdata"][x]["fvTenant"]["attributes"]["name"])
		val = int((json.loads(response.text))["imdata"][x]["fvTenant"]["children"][0]["healthInst"]["attributes"]["cur"])
		tenantHealth[key]=val
	print tenantHealth

	url = "https://10.122.143.24/api/class/fvTenant.json?rsp-subtree-include=faults,no-scoped,subtree&subscription=yes"
	response = get(url, user, cookie)
	key = str((json.loads(response.text))["subscriptionId"])
	subDict[key] = "fault"
	url = "https://10.122.143.24/api/class/fvTenant.json?rsp-subtree-include=faults,no-scoped,subtree&subscription=yes"


#this works --listens on the open websocket for subscribed events
def listen(websocket, user, cookie):
	blank_string=''
	while(1):
		result = websocket.recv()
		print "hit"
		blank_string += blank_string+time.ctime(time.time())+'\n'+json.dumps(json.loads(result), indent=2)+'\n\n'
		f = open('Sub_Output.txt','w')
		f.write(blank_string)
		f.close()


		key = str((json.loads(result))["subscriptionId"])[3:-2]
		#checks the event that the subscription ID we received is mapped tp
		#if we have a fault event, this will extract which tenant the fault was triggered by and then update the user of the change in health score
		if subDict[key] == 'fault':
			time.sleep(20) # we need to look into how to handle the delay-- the apic itself takes a while to update-- im fine leaving a buffer time for now
			print "\n\n\n\n++++++++++++++++Event Generated+++++++++++++++++\n"
			print "Event: "+subDict[str(json.loads(result)["subscriptionId"])[3:-2]]
			temp = str(json.loads(result)["imdata"][0]["faultDelegate"]["attributes"]["dn"]).split('/')
			print "dn --> "+temp[0]+'/'+temp[1]
			url = "https://10.122.143.24/api/mo/"+temp[0]+'/'+temp[1]+".json?rsp-subtree-include=health"
			response = get(url, user, cookie)
			print "Tenant Score Change: "+str(json.loads(response.text)["imdata"][0]['fvTenant']['children'][0]['healthInst']['attributes']['chng'])
			print "New Tenant Health Score: "+str(json.loads(response.text)["imdata"][0]['fvTenant']['children'][0]['healthInst']['attributes']['cur'])
			print "\n++++++++++++++++++++++++++++++++++++++++++++++++\n\n"



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
	time_auth, auth_cookie = get_cookie(ip_addr,username, password)	

	#opening the websocket with the API token
	ws = websocket.WebSocket()#sslopt={"cert_reqs": ssl.CERT_NONE})
	ws.connect("ws://"+ip_addr+"/socket"+auth_cookie['APIC-cookie'])
	thread.start_new_thread(listen, (ws, 'admin', auth_cookie))
	

	while(1):
		#if the auth-cookie has expired we need to ask for a new one
		if cookie_good(time_auth, AUTH_TIMEOUT) == False: 
			time_auth = refresh_cookie(ip_addr, "admin", auth_cookie)

		#input menu for development testing		
		try:
			choice = raw_input("Select 0: Toggle EPG Static Port, 1: Tenant Health, 2: Node Health, 99: POST from file: ")	
			
			#toggle sabatoge to influence health
			if choice == '0':
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: 
					time_auth = refresh_cookie(ip_addr, "admin", auth_cookie)
				sabatoge('admin', auth_cookie)
				print "\n\n"
			
			#get and subscribe to tenant health
			elif choice == '1':
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: 
					time_auth = refresh_cookie(ip_addr, "admin", auth_cookie)				getTenantHealth('admin', auth_cookie)
				print "\n\n"
			
			#get node health **Not implemented yet
			elif choice == '2':
				print "NOT IMPLEMENTED YET"

			#enter post command
			elif choice == '99':
				payload = read_file("post-json.txt")
				if cookie_good(time_auth, AUTH_TIMEOUT) == False: 
					time_auth = refresh_cookie(ip_addr, "admin", auth_cookie), password)
				post(ip_addr,'admin', auth_cookie, payload)
		
		except KeyboardInterrupt :
			print '\n\n\n********************************'
			print '***\t\t\t     ***\n***      Session Closed      ***'
			print '***\t\t\t     ***'
			print '********************************\n\n'
			sys.exit(0)
		






