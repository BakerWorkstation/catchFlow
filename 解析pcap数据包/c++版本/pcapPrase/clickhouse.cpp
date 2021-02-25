#include "clickhouse.h"
#include <iostream>


ClickHouse::ClickHouse(string host,string passwd,string user, int port)
{
    m_client=make_shared<Client>(ClientOptions().SetHost(host).SetPassword(passwd).SetUser(user).SetPort(port));
}

void ClickHouse::MakeTable(string tablename, map<string,string> p)
{
    string sql ="CREATE TABLE IF NOT EXISTS " ;
    string sql2 = " ( ";
    string sql3 = " ) ENGINE = Memory";
    string temp=" ";
    for(auto iter:p)
    {
        
      
            temp=temp+iter.first+" "+iter.second+", ";
        
    }
    temp = temp.substr(0, temp.length() - 2);
    sql =sql +tablename+sql2+temp+" "+sql3;
    cout<<sql<<endl;
    m_client->Execute(sql);
}

void ClickHouse::Insert(string tablename ,Block block)
{
    m_client->Insert(tablename,block);
}