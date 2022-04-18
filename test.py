import shodan

SHODAN_API_KEY = "wbUE6ecabVWGPdiqAIGZJhypQjGKC5OL"
api = shodan.Shodan(SHODAN_API_KEY)
results = api.host('203.246.10.3')
print("""
        IP: {}
        Organization: {}
        Operating System: {}
""".format(results['ip_str'], results.get('org', 'n/a'), results.get('os', 'n/a')))

# Print all banners
for item in results['data']:
        print("""
                Port: {}
                Banner: {}

        """.format(item['port'], item['data']))