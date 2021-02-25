/*
 * @Author: your name
 * @Date: 2020-11-11 10:10:48
 * @LastEditTime: 2020-11-13 16:52:09
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /opt/sniffcatch/clickhouse.h
 */
#include <clickhouse/client.h>
# include <memory>
using namespace clickhouse;
using namespace std;

class ClickHouse
{
    public:
        ClickHouse(string host,string passwd,string user, int port);

        void MakeTable(string tablename, map<string,string> p);
        template <typename T,typename DATA>
        void AppendDatas(T data,DATA list)
        {   //  !!!
             for(auto iter:list)
            {
                data->Append(iter);
            }
        }
        template <typename TT>
        void AppBlock(string name_ck,shared_ptr<TT> name,Block &block)
        {
             block.AppendColumn(name_ck,name);

        }
        void Insert(string tablename ,Block block);

    private:
        shared_ptr<Client> m_client;
};