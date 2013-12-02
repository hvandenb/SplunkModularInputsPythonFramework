#add your custom response handler class to this module
import json
import datetime
#the default handler , does nothing , just passes the raw output directly to STDOUT
class DefaultResponseHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):        
        print_xml_stream(raw_response_output)
        
          
class YammerMessageHandler:
    
    def __init__(self,**args):
        pass
        
    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):

        if response_type == "json":        
            # Need to implement the since message as well...
            output = json.loads(raw_response_output)
            last_yammer_indexed_id = 0
            for yammer_message in output["messages"]:
                message_time = yammer_message["created_at"]
                print_xml_stream(json.dumps(yammer_message))
                if "id" in yammer_message:
                    message_id = yammer_message["id"]
                    if message_id > last_yammer_indexed_id:
                        last_yammer_indexed_id = message_id
            
            if not "params" in req_args:
                req_args["params"] = {}
            
            req_args["params"]["newer_than"] = last_yammer_indexed_id
                       
        else:
            print_xml_stream(raw_response_output)
                    
           
#HELPER FUNCTIONS
    
# prints XML stream
def print_xml_stream(s):
    print "<stream><event unbroken=\"1\"><data>%s</data><done/></event></stream>" % encodeXMLText(s)

    # Need to get the JSON time from the message and use <time>
    # Set SHOULD_LINEMERGE to false



def encodeXMLText(text):
    text = text.replace("&", "&amp;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&apos;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", "")
    return text