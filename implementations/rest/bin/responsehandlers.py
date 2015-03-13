#add your custom response handler class to this module
import json
import datetime
#the default handler , does nothing , just passes the raw output directly to STDOUT
class DefaultResponseHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):        
        print_xml_stream(raw_response_output)
          

class MyResponseHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):        
        print_xml_stream("foobar")

class BoxEventHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if response_type == "json":        
            output = json.loads(raw_response_output)
            if not "params" in req_args:
                req_args["params"] = {}
            if "next_stream_position" in output:    
                req_args["params"]["stream_position"] = output["next_stream_position"]
            for entry in output["entries"]:
                print_xml_stream(json.dumps(entry))   
        else:
            print_xml_stream(raw_response_output)  

class QualysGuardActivityLog:
    '''Response handler for QualysGuard activity log.'''

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if not "params" in req_args:
            req_args["params"] = {}
        date_from = (datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        req_args["params"]["date_from"] = date_from
        print_xml_stream(raw_response_output) 
                          
class FourSquareCheckinsEventHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if response_type == "json":        
            output = json.loads(raw_response_output)
            
            for checkin in output["response"]["checkins"]["items"]:
                print_xml_stream(json.dumps(checkin))   
        else:
            print_xml_stream(raw_response_output)  
          
class BugsenseErrorsEventHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if response_type == "json":        
            output = json.loads(raw_response_output)
            
            for error in output["data"]:
                print_xml_stream(json.dumps(error))   
        else:
            print_xml_stream(raw_response_output)
                     

class TwitterEventHandler:

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):       
            
        if response_type == "json":        
            output = json.loads(raw_response_output)
            last_tweet_indexed_id = 0
            for twitter_event in output["statuses"]:
                print_xml_stream(json.dumps(twitter_event))
                if "id_str" in twitter_event:
                    tweet_id = twitter_event["id_str"]
                    if tweet_id > last_tweet_indexed_id:
                        last_tweet_indexed_id = tweet_id
            
            if not "params" in req_args:
                req_args["params"] = {}
            
            req_args["params"]["since_id"] = last_tweet_indexed_id
                       
        else:
            print_xml_stream(raw_response_output)

class CouchDBEventHandler:

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):       
            
        if response_type == "json":        
            output = json.loads(raw_response_output)
            last_seq = 0
            if output["last_seq"]:
                last_seq = output["last_seq"]

            for couch_event in output["results"]:
                # Make sure this not a design document
                if "id" in couch_event:
                    if not re.match("design", couch_event["id"], re.M|re.I):
                        print_xml_stream(json.dumps(couch_event))

                # if "id_str" in couch_event:
                #     last_seq = couch_event["id_str"]
                #     if last_seq > last_tweet_indexed_id:
                #         last_tweet_indexed_id = last_seq

            
            if not "params" in req_args:
                req_args["params"] = {}
            
            req_args["params"]["since"] = last_seq
                       
        else:
            print_xml_stream(raw_response_output)

                                        
#HELPER FUNCTIONS
    
# prints XML stream
def print_xml_stream(s):
    print "<stream><event unbroken=\"1\"><data>%s</data><done/></event></stream>" % encodeXMLText(s)



def encodeXMLText(text):
    text = text.replace("&", "&amp;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&apos;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", "")
    return text
