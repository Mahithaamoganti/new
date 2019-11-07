import os
import json
import time
import boto3
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

inspector = boto3.client("inspector")

ses = boto3.client("ses")
SES_FROM = "KrishnaChaitanya.ReddyV@cognizant.com"
SES_TO = "kchaitanya556@gmail.com"
SES_SUBJECT = 'Inspector Findings in HTML Format!'
ATTACHMENT = "/tmp/plot.png"
CHARSET = "UTF-8"

def findingsARN(paginator_object, assessmentRunARN):
    
    finding_ARN_High = paginator_object.paginate(assessmentRunArns=[assessmentRunARN], filter={'severities': ['High']})
    finding_ARN_Medium = paginator_object.paginate(assessmentRunArns=[assessmentRunARN], filter={'severities': ['Medium']})
    finding_ARN_Low = paginator_object.paginate(assessmentRunArns=[assessmentRunARN], filter={'severities': ['Low']})
    finding_ARN_Infor = paginator_object.paginate(assessmentRunArns=[assessmentRunARN], filter={'severities': ['Informational']})
    
    findingsARN_High_List = [item for sublist in [x['findingArns'] for x in finding_ARN_High] for item in sublist]
    findingsARN_Medium_List = [item for sublist in [x['findingArns'] for x in finding_ARN_Medium] for item in sublist]
    findingsARN_Low_List = [item for sublist in [x['findingArns'] for x in finding_ARN_Low] for item in sublist]
    findingsARN_Infor_List = [item for sublist in [x['findingArns'] for x in finding_ARN_Infor] for item in sublist]

    for _ in range(2):
        report_url = inspector.get_assessment_report(
            assessmentRunArn=assessmentRunARN,
            reportFileFormat='HTML',
            reportType='FINDING'
        )
        if report_url['status'] == 'WORK_IN_PROGRESS':
            time.sleep(30)
        elif report_url['status'] == 'COMPLETED':
            report_url = report_url['url']
        else:
            print("Some Error has occured. Maybe due to network issues or something else")
    
    
    return rulesPackages(findingsARN_High_List, findingsARN_Medium_List, findingsARN_Low_List, findingsARN_Infor_List, report_url)

def rulesPackages(high, medium, low, infor, url):
    
    if len(high) == 0:
        rpkg_High = []
    else:
        rulepkgARN_List_High = []
        for i in high:
            rulepkgARN_High = inspector.describe_findings(findingArns= [i], locale='EN_US')
            rulepkgARN_List_High.append([x['serviceAttributes']['rulesPackageArn'] for x in rulepkgARN_High['findings']])
    
        rulepkgARN_List_High = [item for sublist in rulepkgARN_List_High for item in sublist]
    
        rpkg_High = []
        for i in rulepkgARN_List_High:
            desc_rulepkg_High = inspector.describe_rules_packages(rulesPackageArns = [i])
            rpkg_High.append(desc_rulepkg_High['rulesPackages'][0]['name'])
    
    if len(medium) == 0:
        rpkg_Medium = []
    else:
        rulepkgARN_List_Medium = []
        for i in medium:
            rulepkgARN_Medium = inspector.describe_findings(findingArns= [i], locale='EN_US')
            rulepkgARN_List_Medium.append([x['serviceAttributes']['rulesPackageArn'] for x in rulepkgARN_Medium['findings']])
    
        rulepkgARN_List_Medium = [item for sublist in rulepkgARN_List_Medium for item in sublist]

        rpkg_Medium = []
        for i in rulepkgARN_List_Medium:
            desc_rulepkg_Medium = inspector.describe_rules_packages(rulesPackageArns = [i])
            rpkg_Medium.append(desc_rulepkg_Medium['rulesPackages'][0]['name'])
    
    if len(low) == 0:
        rpkg_Low = []
    else:
        rulepkgARN_List_Low = []
        for i in low:
            rulepkgARN_Low = inspector.describe_findings(findingArns= [i], locale='EN_US')
            rulepkgARN_List_Low.append([x['serviceAttributes']['rulesPackageArn'] for x in rulepkgARN_Low['findings']])
        
        rulepkgARN_List_Low = [item for sublist in rulepkgARN_List_Low for item in sublist]

        rpkg_Low = []
        for i in rulepkgARN_List_Low:
            desc_rulepkg_Low = inspector.describe_rules_packages(rulesPackageArns = [i])
            rpkg_Low.append(desc_rulepkg_Low['rulesPackages'][0]['name'])
    
    if len(infor) == 0:
        rpkg_Infor = []
    else:
        rulepkgARN_List_Infor = []
        for i in infor:
            rulepkgARN_Infor = inspector.describe_findings(findingArns= [i], locale='EN_US')
            rulepkgARN_List_Infor.append([x['serviceAttributes']['rulesPackageArn'] for x in rulepkgARN_Infor['findings']])
            
        rulepkgARN_List_Infor = [item for sublist in rulepkgARN_List_Infor for item in sublist]

        rpkg_Infor = []
        for i in rulepkgARN_List_Infor:
            desc_rulepkg_Infor = inspector.describe_rules_packages(rulesPackageArns = [i])
            rpkg_Infor.append(desc_rulepkg_Infor['rulesPackages'][0]['name'])
    
    return formatting(high, medium, low, infor, rpkg_High, rpkg_Medium, rpkg_Low, rpkg_Infor, url)

def formatting(high, medium, low, infor, rule_high, rule_medium, rule_low, rule_infor, url):
    
    # High Findings
    if len(high) == 0:
        high_output = []
    else:
        
        instanceid_High = []
        severity_High = []
        
        for i in high:
        
            high_findings = inspector.describe_findings(findingArns= [i], locale='EN_US')

            instanceid_High.append(high_findings['findings'][0]['assetAttributes']['agentId'])
            severity_High.append(high_findings['findings'][0]['severity'])
        
        high_output = list(zip(instanceid_High, rule_high, severity_High))
        
    # Medium Findings
    if len(medium) == 0:
        medium_output = []
    else:
        
        instanceid_medium = []
        severity_medium = []
        
        for i in medium:
            
            medium_findings = inspector.describe_findings(findingArns= [i], locale='EN_US')
            
            instanceid_medium.append(medium_findings['findings'][0]['assetAttributes']['agentId'])
            severity_medium.append(medium_findings['findings'][0]['severity'])
  
        medium_output = list(zip(instanceid_medium, rule_medium, severity_medium))
    
    # Low Findings
    if len(low) == 0:
        low_output = []
    else:
        
        instanceid_low = []
        severity_low = []
        
        for i in low:
        
            low_findings = inspector.describe_findings(findingArns= [i], locale='EN_US')
  
            instanceid_low.append(low_findings['findings'][0]['assetAttributes']['agentId'])
            severity_low.append(low_findings['findings'][0]['severity'])
    
        low_output = list(zip(instanceid_low, rule_low, severity_low))

    # Informational Severity
    if len(infor) == 0:
        infor_output = []
    else:
        
        instanceid_infor = []
        severity_infor = []
        
        for i in infor:
            
            infor_findings = inspector.describe_findings(findingArns= [i], locale='EN_US')

            instanceid_infor.append(infor_findings['findings'][0]['assetAttributes']['agentId'])
            severity_infor.append(infor_findings['findings'][0]['severity'])
  
        infor_output = list(zip(instanceid_infor, rule_infor, severity_infor))
    
    combined_output = high_output + medium_output + low_output + infor_output

    df = pd.DataFrame(combined_output, columns = ["InstanceID", "Rules Packages", "Severity"])
    
    return visualsandhtml(df, high, medium, low, infor, url)
    
def visualsandhtml(df, high, medium, low, infor, url):
    
    if len(high) == 0:
        high_count = 0
    else:
        high_count = len(df[df['Severity'] == "High"])
    
    if len(medium) == 0:
        medium_count = 0
    else:
        medium_count = len(df[df['Severity'] == "Medium"])
    
    if len(low) == 0:
        low_count = 0
    else:
        low_count = len(df[df['Severity'] == "Low"])
        
    if len(infor) == 0:
        infor_count = 0
    else:
        infor_count = len(df[df['Severity'] == "Informational"])
    
    df['Rules Packages'] = df['Rules Packages'].replace({"CIS Operating System Security Configuration Benchmarks" : "CIS OS Benchmarks"})
    df['Rules Packages'] = df['Rules Packages'].replace({"Common Vulnerabilities and Exposures" : "CVE"})

    
    plt.figure(figsize = (10, 10))
    ax = sns.countplot(x = df['Rules Packages'], hue = df['Severity'], data = df, palette="bright")
    for p in ax.patches:
        height = p.get_height()
        ax.text(p.get_x() + p.get_width() / 2 , height + 1, '{0}'.format(height) ,ha="center")
    plt.title("Count of Vulnerabilities wrt. Rules Packages")
    plt.xlabel("Severity")
    plt.xticks(rotation = 30)
    plt.ylabel("Count")
    plt.savefig("/tmp/plot.png")

    body_html_1 = """
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="utf-8">
        </head>
        <br>
        <body>
            <h3> AWS Inspector Findings </h3>
            <p><font color="Red">High Severity Count</font>: %s</p>
            <p><font color="#ffbf00">Medium Severity Count</font>: %s</p>
            <p><font color="#006400">Low Severity Count</font>: %s</p>
            <p><font color="#32CD32">Informational Count</font>: %s</p>
            <br>
            <p>Detailed report for the findings can be accessed <a href=%s>here</a></p>
            <p>Please refer the attached visual for more details</p>
        </body>
    </html>
    """ % (high_count, medium_count, low_count, infor_count, url)
    msg = MIMEMultipart('mixed')
    msg['Subject'] = SES_SUBJECT 
    msg['From'] = SES_FROM
    msg['To'] = SES_TO
    
    msg_body = MIMEMultipart('alternative')
    
    htmlpart = MIMEText(body_html_1.encode(CHARSET), 'html', CHARSET)
    
    msg_body.attach(htmlpart)
    
    att = MIMEApplication(open(ATTACHMENT, 'rb').read())
    
    att.add_header('Content-Disposition','attachment',filename=os.path.basename(ATTACHMENT))
    
    msg.attach(msg_body)
    
    msg.attach(att)
    try:
        response = ses.send_raw_email(
            Source=SES_FROM,
            Destinations=[
                SES_TO
            ],
            RawMessage={
                'Data':msg.as_string(),
            },
        )    
    except:
        print("Some Error has occured")
    else:
        print("Email sent! Message ID: %s" % response['MessageId'])
  
    return 0

def lambda_handler(event, context):
    time.sleep(30)
    try:
        message = event['Records'][0]['Sns']['Message']
        assessmentRun = message['run']
    except:
        print("Error might be in json loads.")

    paginator = inspector.get_paginator('list_findings')
    
    findingsARN(paginator, assessmentRun)
    
    return 0
