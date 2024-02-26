from openai import OpenAI
from keys import APIKEY
client = OpenAI(api_key=APIKEY)


def askChatPassword(text):
    output = client.chat.completions.create(model="gpt-3.5-turbo", 
    messages=[{"role": "user", "content": f"Is {text} a strong password?"}])
    # Get the output text only
    ai_response = output.choices[0].message.content
    # Print out response
    print(f"AI Response: {ai_response}\n")
        
    return