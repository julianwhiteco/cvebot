import requests
from bs4 import BeautifulSoup
import re


# Input validator
def lookup_check(term):
    print(f"Input: {term}")
    # Replace spaces with '-' if term is like 'CVE 2022 37971'
    if re.match(r'^CVE \d{4} \d+$', term):
        term = term.replace(' ', '-')

    # Check if term contains any non-alphanumeric characters except spaces
    elif re.search(r'[^\w\s-]+', term) and not re.match(r'^\d{4} \d+$', term):
        return None  # return None as error code

    # If term contains only digits, format it as a CVE ID
    elif term.isdigit():
        if len(term) == 9:  # if the term is like '202338245'
            term = f"CVE-{term[:4]}-{term[4:]}"  # format it as 'CVE-2023-38245'
        else:
            term = term.replace(' ', '-')
            term = "CVE-" + term  # prepend 'CVE-' to the term
    elif re.match(r'^\d{4} \d+$', term):  # if term is like '2023 38245'
        term = "CVE-" + term.replace(' ', '-')  # format it as 'CVE-2023-38245'

    print(f"Output: {term}")
    return term


# Fetch the total number of results.
def get_total(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    info_box = soup.find('span', class_='info-box-number')
    if info_box:
        text_content = info_box.text.strip()
        total = text_content.replace(' CVE', '')
        return int(total)


# Get the first five results from the lookup table.
def get_table_data(soup):
    base_url = 'https://www.opencve.io/cve/'
    table = soup.find('table')
    if table is None:
        return []
    table_data = []
    rows = table.find_all('tr')
    count = 0
    for i in range(0, len(rows), 2):  # Loop through every two rows
        if count >= 5:  # Limit the number of responses to 5
            break
        row_data = []
        for j in range(2):  # Process the current row and the next row
            cells = rows[i + j].find_all('td')
            if cells:
                cell_contents = [cell.text.strip() for cell in cells]
                row_data.extend(cell_contents)
        cve_id = row_data[0]
        url = base_url + cve_id
        explanation = row_data[-1].split('. ')[0] + '.'  # Keep text only before the first "."
        if len(explanation) > 100:  # Truncate explanation if longer than 100 characters
            explanation = explanation[:97] + '...'  # Include '...' in the 100 characters
        row_data[-1] = url
        row_data.append(explanation)
        table_data.append(row_data)
        count += 1
    return table_data


# Run this via telegram; if it returns table send to user. 0 is no response. And 1 contains illegal char.
def main(search_term):
    # Base URL
    url = 'https://www.opencve.io/cve'

    # Query parameters
    formatted_term = lookup_check(str(search_term))
    print(formatted_term)

    if formatted_term is None:
        print(f"Error: Your search '{search_term}' contained an illegal character.")
        return 1
    else:
        params = {
            'cvss': '',
            'search': formatted_term
        }

        url = 'https://www.opencve.io/cve'
        response = requests.get(url, params=params)


        # Start...
        print(f'Searching for: {formatted_term}')

        # Call the get_total function to get the total number of results
        total = get_total(response.text)

        # Proceed only if total is greater than 0
        if total > 0:
            print(f'Total number of results: {total}')
            soup = BeautifulSoup(response.text, 'html.parser')
            table_data = get_table_data(soup)
            # for row_data in table_data:
            #     print(row_data)

            # Print the URL for continuing reading - do this via telegram bot stage.
            print(total)
            if total > 5:
                print(f"More results at: {response.url}")
            return total, table_data

        else:
            print("No results found.")
            return 0


# main(str("microsoft"))
print(main(str("microsoft")))
