import requests
import streamlit as st
import pandas as pd


#연결 상태 확인
def check_connect(api_key):
    url = "https://api.criminalip.io/v1/user/me"
    payload={}
    headers = {
      "x-api-key": api_key
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    j_res=response.json()
    if j_res['message']== "success":
        return True
    return j_res['status']

def malicious_data(ip,api_key):
    url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={ip}"
    payload={}
    headers = {"x-api-key": api_key}
    response = requests.request("GET", url, headers=headers, data=payload)
    res_j=response.json()
    return res_j

def get_ip(j_data):
    return j_data['ip']

def get_ports(j_data):
    ports=[]
    for port in j_data['current_opened_port']['data']:
        ports.append([port['port'],port['protocol'],port['product_name'],str(port['has_vulnerability'])])
    ports.sort()
    ports_df=pd.DataFrame(ports,columns=['Open Port','Protocol','Product Name','vulnerability'])        
    return ports_df 

def get_vuln(j_data):
    vulns_list=[]
    vulns=j_data['vulnerability']['data']
    for vuln in vulns:
        if vuln['cvssv3_score'] !=0.0:
            vulns_list.append([vuln['ports']['tcp'],vuln['cve_id'],vuln['cvssv3_score']])
    vulns_list.sort(key=lambda x:x[0])
    vuln_df=pd.DataFrame(vulns_list,columns=['Port','CVE ID','CVSSV3 Score'])
    return vuln_df

def get_vpn(j_data):
    return j_data['is_vpn']

def summary_data(ip,api_key):
    url = f"https://api.criminalip.io/v1/ip/summary?ip={ip}"

    payload={}
    headers = {"x-api-key": api_key}

    response = requests.request("GET", url, headers=headers, data=payload)
    j_res=response.json()
    return j_res

def get_country(j_data):
    return '{}, {}, {}'.format(j_data['city'],j_data['region'],j_data['country'])

def get_inbound(j_data):
    return j_data['score']['inbound']

def get_outbound(j_data):
    return j_data['score']['outbound']



def main():
    #기본 UI
    st.title('IP Checker')
    ip=st.text_input("IP")
    api_key=st.text_input("Criminal_Ip API KEY", type="password")
    submit=st.button('Check')

    #버튼 액션
    if submit:
        tmp=check_connect(api_key)
        if tmp==True:
            m_data=malicious_data(ip,api_key)
            s_data=summary_data(ip,api_key)
            st.subheader('Information')
            st.write(f'IP : {get_ip(m_data)}')
            st.write(f'Location : {get_country(s_data)}')
            st.write(f'VPN : {get_vpn(m_data)}')
            st.write(f'Inbound Score : {get_inbound(s_data)}')
            st.write(f'Outbound Score : {get_outbound(s_data)}')

            st.subheader('Open Port')
            st.table(get_ports(m_data))

            st.subheader('Vulnerability')
            st.dataframe(get_vuln(m_data))
                        
        else:
            st.write(f'{tmp} Error')


if __name__=='__main__':
    main()