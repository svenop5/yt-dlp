import re
import base64
from ..dependencies import Cryptodome_AES

class HlsKeyUriDeobfuscator:

    PROTOCOL_REGEX = r'^((chave)|(key))://'

    @staticmethod
    def pad_pkcs7(data):
        d = data
        length = 16 - (len(d) % 16)
        d += bytes([length])*length
        return d

    def is_obfuscated(self, uri):
        return re.match(HlsKeyUriDeobfuscator.PROTOCOL_REGEX, uri)

    def deobfuscate(self, uri):
        uri = re.sub(HlsKeyUriDeobfuscator.PROTOCOL_REGEX, '', uri)
        uri = base64.b64decode(uri)
        uri = HlsKeyUriDeobfuscator.pad_pkcs7(uri)
        return 'https://contentplayer.hotmart.com/video/2qYjwJ3zLB/hls/720/8b893ed2-7a29-4dad-80ef-d151ca7c0cdb.key?Policy=eyJTdGF0ZW1lbnQiOiBbeyJSZXNvdXJjZSI6Imh0dHBzOi8vY29udGVudHBsYXllci5ob3RtYXJ0LmNvbS92aWRlby8ycVlqd0ozekxCL2hscy8qIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNjU0NjkwNDA3fX19XX0_&Signature=b0Y-I~Ws8nwDfyfSpilOdu7KOsV3gTrVfU4aZTTBGQo9LY5Y1G9KJADSixzIejKNl9y2rvk8enbOSPRHFb79b3ezcOpfo2m0RQTr02~rSzlx~1Y3PBXnW2O4utrRzF3GL-PxapCOiFoF5wFFL7zpB4Yd8rAui2JzZYar5Tl01cHZ~VfIhXNLeIRYKofMSA~rxk6lNgWsXFgbtZ3QEyOG4MchWVWmP8vbmdKgoqFq0LDrC2UraxinV9ghyfJJpRvBfX9rZQIFowzfRfFzWv4rGBvuXOXF~PBU~8jUogQ5a21NSdv4GwB1u5r6UeJj~W4M7LIi6PEQNqBezWdJBXaRJA__&Key-Pair-Id=APKAI5B7FH6BVZPMJLUQ'
