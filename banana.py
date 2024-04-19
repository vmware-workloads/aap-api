import uuid
import json
import requests
import time
import os
import traceback
import urllib3
urllib3.disable_warnings()



def handler(context, inputs):
    greeting = "Hello, {0}!".format(inputs["target"])
    print(greeting)

    outputs = {
      "greeting": greeting
    }

    return outputs
