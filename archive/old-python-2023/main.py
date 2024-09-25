import os
import requests
from bs4 import BeautifulSoup
import re
import telebot
import sys
import time


# todo section
# - create an /about handler that prints about (author, data source) and current config ie rate limiting (6 requests per 60 secs)
# - add a keyboarding option - start with 'new search'


if len(sys.argv) < 2:
    print("Usage: python app.py <API_KEY>")
    sys.exit(1)
api_key = sys.argv[1]

user_requests = {}
REQUEST_LIMIT = 6
TIME_LIMIT = 60


# Input validator
def lookup_check(term):
    # print(f"Input: {term}")
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

    # print(f"Output: {term}")
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
        row_data[-1] = url
        row_data.append(explanation)
        table_data.append(row_data)
        count += 1
    return table_data


# Run this via telegram; if it returns table send to user. 0 is no response. And 1 contains illegal char.
def main_check(search_term):
    formatted_term = lookup_check(search_term)
    if formatted_term is None:
        return 1, f"Error: Your search '{search_term}' contained an illegal character.", None, None

    params = {'cvss': '', 'search': formatted_term}
    try:
        response = requests.get('https://www.opencve.io/cve', params=params, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return -1, str(e), None, None
    total = get_total(response.text)
    url = response.url  # store the URL
    if total == 0:
        return 0, "No results found.", total, url
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        table_data = get_table_data(soup)
        return 2, table_data, total, url  # return the URL


def format_cve_data(row):
    cve_id, _, product, date, _, score, url, description = row
    vendor_match = re.search(r'\d (.+)', row[1])
    vendor = vendor_match.group(1) if vendor_match is not None else ''
    product_match = re.search(r'\d (.+)', product)
    product = product_match.group(1) if product_match is not None else product
    product_vendor_text = ''
    if product or vendor:
        product_vendor_text = f"<i>{product} ({vendor})</i>\n" if vendor else f"{product} "
    description = description if len(description) <= 120 else description[:117] + "..."
    message = (
        f'<b><a href="{url}">{cve_id}</a></b>\n'
        f"{product_vendor_text}"
        f"Reported {date} | "
        f"<b>Score:</b> {score.split(' ')[0]} \n"
        f"{description} "
        f' <a href="{url}">read more</a>'
    )
    return message


def main():
    bot = telebot.TeleBot(api_key)

    @bot.message_handler(func=lambda message: True)
    def handle_message(message):
        user_id = message.from_user.id
        current_time = time.time()

        if user_id in user_requests:
            last_request_time, request_count = user_requests[user_id]
            if current_time - last_request_time < TIME_LIMIT:
                if request_count >= REQUEST_LIMIT:
                    bot.reply_to(message, "Request limit exceeded. Please wait a minute.")
                    return
                user_requests[user_id] = (last_request_time, request_count + 1)
            else:
                user_requests[user_id] = (current_time, 1)
        else:
            user_requests[user_id] = (current_time, 1)

        result_code, result_data, total, url = main_check(message.text)

        if result_code == 0 or result_code == 1:
            bot.reply_to(message, result_data)
        elif result_code == 2:
            formatted_data = "\n\n".join(format_cve_data(row) for row in result_data)  # formatting each row
            reply = f"<b>Total Results: </b>{total}\nLatest:\n\n{formatted_data}"
            if total > 5:  # only include the URL if total is greater than 5
                reply += f"\n\nMore results at: {url}"
            bot.send_message(message.chat.id, reply, parse_mode='HTML', disable_web_page_preview=True)

    bot.polling(none_stop=True)


main()

