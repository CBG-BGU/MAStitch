import requests
import json
import os
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


class InternetSearchTool(BaseTool):
    name: str = "Internet Search Tool"
    description: str = "Search the internet for information about security threats, attack patterns, or suspicious activities utilize the user input"

    def _run(self, query: str) -> str:
        """Search the internet and return results"""
        try:
            # Use environment variable for API key
            if 'SERPER_API_KEY' not in os.environ:
                return "Search tool unavailable: API key not configured"

            url = "https://google.serper.dev/search"
            payload = json.dumps({"q": query})
            headers = {
                'X-API-KEY': os.environ['SERPER_API_KEY'],
                'content-type': 'application/json'
            }

            response = requests.request("POST", url, headers=headers, data=payload)
            if response.status_code != 200:
                return f"Search failed with status code: {response.status_code}"

            results = response.json().get('organic', [])
            search_results = []

            for result in results[:2]:  # Limit to 3 results to reduce token usage
                try:
                    search_results.append('\n'.join([
                        f"Title: {result['title']}",
                        f"Link: {result['link']}",
                        f"Snippet: {result['snippet']}",
                        "\n-----------------"
                    ]))
                except KeyError:
                    continue

            content = '\n'.join(search_results)
            return f"\nSearch results for '{query}':\n{content}\n" if content else "No relevant results found."

        except Exception as e:
            return f"Search error: {str(e)}"
