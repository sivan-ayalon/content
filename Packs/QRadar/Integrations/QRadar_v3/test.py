from apiclient.discovery import build
from google.oauth2 import service_account

# Specify required scopes.
SCOPES = ['https://www.googleapis.com/auth/chat.bot']

# Specify service account details.
CREDENTIALS = service_account.Credentials.from_service_account_file(
    '/Users/jbabazadeh/Downloads/jchattest-426717-02ee67793186.json', scopes=SCOPES)

# Build the URI and authenticate with the service account.
chat = build('chat', 'v1', credentials=CREDENTIALS)

# Create a Chat message.
result = chat.spaces().messages().create(

    # The space to create the message in.
    #
    # Replace SPACE_NAME with a space name.
    # Obtain the space name from the spaces resource of Chat API,
    # or from a space's URL.
    parent='spaces/AAAAymdLsLE',

    # The message to create.
    # body={'text': 'Hello, world!'}
    body={
        "cards": [
            {
            "header": {
                "title": "Feedback required"
            },
            "sections": [
                {
                "widgets": [
                    {
                    "textParagraph": {
                        "text": "Do you approve this action?"
                    }
                    },
                    {
                    "buttons": [
                        {
                        "textButton": {
                            "text": "Yes",
                            "onClick": {
                            "action": {
                                "actionMethodName": "Yes_action"
                            }
                            }
                        }
                        },
                        {
                        "textButton": {
                            "text": "No",
                            "onClick": {
                            "action": {
                                "actionMethodName": "No_action"
                            }
                            }
                        }
                        },
                        {
                        "textButton": {
                            "text": "Don't know",
                            "onClick": {
                            "action": {
                                "actionMethodName": "Dont_know_action"
                            }
                            }
                        }
                        }
                    ]
                    }
                ]
                }
            ]
            }
        ]
        }
).execute()

# Prints details about the created message.
print(result)