'''
Created on 2015-10-22
Created by @xploresec. Super thanks to @pathetiq
@version: 0.1
@summary: This BurpSuite extension is based on the work of Burpy available here: https://github.com/debasishm89/burpy
What this extension can do:
- CSRF testing: It accepts an Anti-CSRF token and a request failure message. For every request Anti-CSRF token is removed and request is resent followed by checking response for CSRF failure message.
- Add/Remove HTTP headers
- Add/Remove request parameters
- Generate HTML report

[IMPORTANT] How to use: Modify line 68-90 and 128-144 for this extension to work according to your requirements.
'''

from burp import IBurpExtender
from burp import IHttpListener
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from burp import IParameter
from array import array
from java.io import PrintWriter
from urlparse import urlparse
from os.path import splitext, basename
from java.net import URL, URLEncoder

class BurpExtender(IBurpExtender,IHttpListener, IBurpExtenderCallbacks):

    # definitions
    EXTENSION_NAME = "Request Buster"

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
       
        # define stdout writer
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        print(self.EXTENSION_NAME + ' by @xploresec. Super thanks @pathetiq')
        print('================================')
        print('This plugin is based on the work of Burpy available here: https://github.com/debasishm89/burpy\n')
        print('================================\n\n')        
        # set our extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerHttpListener(self)
        
        return

    def extensionUnloaded(self):
        print("Extension was unloaded")
        return
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo): #IHttpRequestResponse message info
        #get an Urldata object / Object is define later
        if messageIsRequest and toolFlag != self._callbacks.TOOL_EXTENDER: #this is required to not LOOP Forever!
            #print("Request Received")
            data = self.getURLdata(messageInfo) 
            url = str(data[0])
            params = str(data[1])
            #make http request test
            self.testRequest(url, messageInfo)
            
        return
    
    def testRequest(self, url, messageInfo):
        ########### CONFIGURATION START ###########
        #Host name for which you want to perform CSRF check and other attacks
        host_name = "localhost"
        #File extensions that you don't want to test (lowercase only)
        skip_extensions = ["jpg","jpeg","png","gif","svg","css","js"]
        #Which HTTP methods should be tested? Example: ["GET", "POST", "PUT"]
        allowed_http_methods = ["POST"]
        #Do you want to test for CSRF? True/False
        csrf_check = True
        #Name of the Anti-CSRF parameter in your application
        anti_csrf_param = '_wpnonce'
        #Message shown when the CSRF parameter is not sent in the request
        csrf_fail_message = 'Are you sure you want to do this'
        #Do you want to print original request? True/False
        print_original_request = True
        #Do you want to print modified request? True/False
        print_modified_request = True
        #Do you want to print response for modified request? True/False
        print_modified_request_response = False
        #Write to HTML file configuration
        save_to_html = True
        save_filepath = "c:\\temp\\report_test.html"
        ########### CONFIGURATION END ###########
        
        #Check if the host is in scope for testing
        if host_name != URL(str(url)).getHost():
            return
        
        #Check if the HTTP method is allowed for testing
        if ((self._helpers.analyzeRequest(messageInfo)).getMethod()).upper() not in allowed_http_methods:
            return
        
        #Check if the file name is in scope for testing
        if not self.isAllowedFileName(str(url), skip_extensions):
            return
        
        #Get the url and data to create the new URL request
        urlString = str(url)#cast to cast to stop the TYPEerror on URL()

        #Java URL to be used with Burp API
        url = URL(urlString)
        #print "UrlString: "+urlString

        #Build the new request    
        newRequest = None
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        #Get current request
        currentRequest = self._helpers.bytesToString(messageInfo.getRequest());
        #Get the request body
        messageBody = currentRequest[requestInfo.getBodyOffset():];
        list_messageBody = messageBody.split('&')
        final_messageBody = ""
        final_list_messageBody = list_messageBody
        #Get headers in original request
        headers = requestInfo.getHeaders()
        #Data variables
        data_original_request = ""
        data_modified_request = ""
        data_modified_request_response = ""
        
        ########### [Start] ADD/REMOVE Content ###########
        #Add new headers
        #Syntax: headers = self.addHeader(headers, 'header_name', 'header_value')
        #headers = self.addHeader(headers, 'newheader', 'newheaderval')
        
        #Remove header from request
        #Syntax: headers = self.removeHeader(headers, 'header_name')
        headers = self.removeHeader(headers, 'Referer') # Do not remove. This is important for CSRF testing
        
        #Add a parameter to message body
        #Syntax: final_messageBody = self.addParameter(final_messageBody, 'new_param_name', 'new_param_value')
        #final_messageBody = self.addParameter(final_messageBody, 'newparam', 'newparamvalue')
        
        #Remove a parameter from message body
        #Syntax: final_messageBody = self.removeParameter(final_messageBody, 'existing_param_name')
        #list_messageBody = self.removeParameter(list_messageBody, 'asd')
        ########### [End] ADD/REMOVE Content ###########
        
        #Check if CSRF check is to be performed or not
        if csrf_check:
            #Remove anti-csrf token from request
            final_list_messageBody = filter(lambda x: not x.startswith(anti_csrf_param+'='), list_messageBody)
        #Add all params to message body string
        for param in final_list_messageBody:
            final_messageBody = final_messageBody + param + '&'
        
        #Remove trailing "&" from the POST message body
        final_messageBody = final_messageBody[:-1] if final_messageBody.endswith('&') else final_messageBody
        
        #Prepare the final POST request message body
        final_messageBody = bytearray(final_messageBody.encode('ascii', 'ignore'))
        
        #VERIFICATION: when port isn't define in the URL it is equals to -1, so we set it back to http
        if url.getPort() <= 0:
            if url.getProtocol() == "https":
                port = 443
            else:
                port = 80
        else:
            port = url.getPort()
        
        
        #Build newRequest
        if len(final_messageBody)!=0:
            newRequest = self._helpers.buildHttpMessage(headers, final_messageBody)
        else:
            newRequest = self._helpers.buildHttpMessage(headers, None)
        #Execute the request 
        newResponse = self._callbacks.makeHttpRequest(url.getHost(), port, url.getProtocol() == "https", newRequest)
        newResponseString = self._helpers.bytesToString(newResponse)
        new_response_str =  newResponseString.encode('ascii', 'ignore')
        
        #Set data in data variables
        data_original_request = self._helpers.bytesToString(messageInfo.getRequest())
        data_modified_request = self._helpers.bytesToString(newRequest)
        data_modified_request_response = new_response_str
        csrf_check_status = False
        
        #Print original request
        if print_original_request:
            print "Original Request:\n"
            print data_original_request
        #Print modified request
        if print_modified_request:
            print "\n\nModified Request:\n"
            print data_modified_request
        #Print response of modified request
        if print_modified_request_response:
            print "\n\nResponse for Modified Request:\n"
            print data_modified_request_response + "\n"
        #Perform CSRF check
        if csrf_check:
            if csrf_fail_message not in new_response_str:
                csrf_check_status = True
                print "******|| CSRF found in this request ||******\n"
        #Save to HTML report report
        if save_to_html:
            f = open(save_filepath, "a")
            f.write("<table border='1' width='100%'><tr><td>")
            if print_original_request:
                f.write("<b>Original Request:</b><br>")
                f.write("<pre style='white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;'>")
                f.write(data_original_request.replace("\r\n","\n"))
                f.write("</pre>")
                f.write("<br><br>")
            if print_modified_request:
                f.write("<b>Modified Request:</b><br>")
                f.write("<pre style='white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;'>")
                f.write(data_modified_request.replace("\r\n","\n"))
                f.write("</pre>")
                f.write("<br><br>")
            if print_modified_request_response:
                f.write("<b>Response for Modified Request:</b><br>")
                f.write("<pre style='white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;'>")
                f.write(data_modified_request_response.replace("\r\n","\n"))
                f.write("</pre>")
                f.write("<br><br>")
            if csrf_check and csrf_check_status:
                f.write("<b>CSRF check status: <font color='red'>FOUND</font></b>")
                f.write("<br><br>")
            f.write("</td></tr></table><br><br>")
            f.close()
        print ("="*100)+"\n"
    
    '''
    This function checks if the filename in URL is allowed for testing
    '''
    def isAllowedFileName(self, target_url, skip_ext):
        disass = urlparse(target_url)
        file_name,file_ext = splitext(basename(disass.path))
        if file_ext.lower() in skip_ext:
            return False
        return True

    '''
    This function adds a new header to the request
    '''
    def addHeader(self, headers, headerName, headerValue):
        headers.add(headerName+': '+headerValue)
        return headers
        
    '''
    This function removes an existing header to the request
    '''
    def removeHeader(self, headers, headerName):
        headers = filter(lambda x: not x.startswith(headerName+':'), headers)
        return headers

    '''
    This function removes an existing header from the request
    '''
    def addParameter(self, final_messageBody, new_param_name, new_param_value):
        final_messageBody = final_messageBody + new_param_name + '=' + new_param_value + '&'
        return final_messageBody
    
    '''
    This function removes an existing parameter from the request
    '''
    def removeParameter(self, list_messageBody, existing_param_name):
        return filter(lambda x: not x.startswith(existing_param_name+'='), list_messageBody)
    
    '''
    This functions split all informations of the URL 
    '''
    def getURLdata(self,messageInfo):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        #print (url)
        
        #Is there any parameters?
        params = self._helpers.analyzeRequest(messageInfo).getParameters()
        
        for p in params:
            pass
            #print "Query var: "+p.getName()
            #print "Query value: "+p.getValue() 
                
        
        return url,params 
      
      
