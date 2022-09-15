#!/usr/bin/env python
import requests
import sys
from datetime import datetime, timezone, timedelta
import pytz
import pandas as pd

def utcformat(dt, timespec='milliseconds'):
    """convert datetime to string in UTC format (YYYY-mm-ddTHH:MM:SS:mmmZ)"""
    iso_str = dt.astimezone(timezone.utc).isoformat('T', timespec)
    return iso_str.replace('+00:00', ' Z').replace('.', ':')

def sendNoti(result):
    time = datetime.now(tz=pytz.timezone("Asia/Ho_Chi_Minh")).strftime("%d/%m/%Y %H:%M:%S")
    result = time + "\n" + result
    url = "https://chat.googleapis.com/v1/spaces/AAAAZmksR6A/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=XUcu3fzGlA4BjkPpcAWCecYlffN9i2iNfdy8wB9Tr6I%3D"
    data = {'text':result}
    x = requests.post(url, json=data)

def readFile():
    df = pd.read_excel(r'MoMo Lib Version.xlsx', sheet_name='Sheet2')
    result = {}
    result['name'] = df['Service & Lib'].to_dict()
    result['version'] = df['Version'].to_dict()
    return result

def getListCVEs():
    current_date = datetime.now()
    pre_date = datetime.now() - timedelta(1)
    result = requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=200&pubStartDate='+ utcformat(pre_date) + '&pubEndDate=' + utcformat(current_date))
    result_json = result.json()
    print('https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=200&pubStartDate='+ utcformat(pre_date) + '&pubEndDate=' + utcformat(current_date))
    print(result_json)
    sendNoti("Range time: " + pre_date.strftime("%d/%m/%Y %H:%M:%S") + " to " + current_date.strftime("%d/%m/%Y %H:%M:%S"))
    return result_json

def main():
    results_count = 0
    patern = readFile()

    cveslist = getListCVEs()


    if cveslist['resultsPerPage'] == 0:
        sendNoti('Không có dữ liệu!')
        sys.exit()
    CVE_Items = cveslist['result']['CVE_Items']
    for i in CVE_Items:
        id = i['cve']['CVE_data_meta']['ID']
        detail = i['cve']['description']['description_data'][0]['value']
        link = 'https://nvd.nist.gov/vuln/detail/' + id
        if len(i['impact']) == 0:
            score = 'N/A'
            severity = 'N/A'    
        else:
            score = i['impact']['baseMetricV3']['cvssV3']['baseScore']
            severity = i['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        for p in range(0, len(patern['name'])):
            if (detail.find(patern['name'][p]) != -1) and (detail.find(str(patern['version'][p])) != -1):
                sendNoti("*ID:* " + id + "\n*Details:* " + detail + "\n*Score:* " + str(score) + "\n*Severity:* " + severity +"\n*Link:* " + link + "\n*Search string:* " + patern['name'][p] + " " + patern['version'][p])
                results_count+=1
    if results_count == 0:
        sendNoti('Không có dữ liệu!')

if __name__ == "__main__":
    main()
