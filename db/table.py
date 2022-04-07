import sqlite3 as sql
from flask import abort

from db.connect import dbConnection

class TargetSiteTable:
    def __init__(self):
        self.__table_name__ = "target_site"
        self.con = dbConnection()

    def __del__(self):
        self.con.close()

    def insertDomain(self, domain: str):
        """ domain 값을 삽입하는 함수

        Args:
            - domain: 삽입하려는 도메인을 인자로 받음.
        
        Usage:
            - insertDomain('naver.com')
        """
        
        ##  이미 domain 정보가 삽입 되었을 경우, 추가로 삽입하지 않음.
        if len(self.getDomainInfo(domain)) != 0:
            return

        query = """
            INSERT INTO {table_name} (domain) 
            VALUES (?)
        """.format(table_name = self.__table_name__)

        self.con.cursor().execute(query, (domain, ))
        self.con.commit()
    

    def getDomainInfo(self, domain: str) -> list:
        """ domain 정보를 가져오기 위한 함수

        Args:
            - domain: 조회 하려는 도메인을 인자로 받음.
        
        Usage:
            - getDomainInfo('naver.com')
        """

        query = """
            SELECT * FROM {table_name}
            WHERE domain = ?
        """.format(table_name = self.__table_name__)

        cur = self.con.cursor()
        cur.execute(query, (domain, ))
        
        return cur.fetchall()


class SubdomainTable:
    def __init__(self):
        self.__table_name__ = "subdomain"
        self.con = dbConnection()

    def __del__(self):
        self.con.close()

    def insertSubdomain(self, subdomains_data: list, domain: str):
        """ 여러개의 subdomain 값을 삽입하는 함수

        Args:
            - subdomains: 삽입하려는 list 형태의 서브도메인 정보를 인자로 받음.
            - domain: 서브도메인의 도메인 정보가 필요함.
        
        Usage:
            - insertSubdomain([
                                {
                                    "site" : "a.target.com",
                                    "status_code" : 200
                                },
                                ...
                            ], "target.com")
        """

        target_site_data = TargetSiteTable().getDomainInfo(domain)
        if len(target_site_data) == 0:
            return
        
        target_idx = target_site_data[0][0]
        self.deleteSubdomain(target_idx)

        query = """
            INSERT INTO {table_name} (subdomain, status_code, target_idx)
            VALUES (?, ?, ?)
        """.format(table_name = self.__table_name__)
        
        for data in subdomains_data:
            self.con.cursor().execute(query, (data["site"], data["status_code"], target_idx, ))
            self.con.commit()


    def deleteSubdomain(self, target_idx: int):
        query = """
            DELETE FROM {table_name}
            WHERE target_idx = ?
        """.format(table_name = self.__table_name__)

        self.con.cursor().execute(query, (target_idx, ))
        self.con.commit()

    
    def getSubdomain(self, domain: str) -> list:
        """ subdomain 정보를 가져오기 위한 함수

        Args:
            - domain: 조회 하려는 서브도메인의 도메인
        
        Usage:
            - getSubomain('naver.com')
        """
        target_site_data = TargetSiteTable().getDomainInfo(domain)
        if len(target_site_data) == 0:
            return
        
        target_idx = target_site_data[0][0]

        query = """
            SELEST FROM {table_name}
            WHERE target_idx = ?
        """.format(table_name = self.__table_name__)

        cur = self.con.cursor()
        cur.execute(query, (target_idx, ))
        
        return cur.fetchall()


class TodoTable:
    def __init__(self):
        self.__table_name__ = "todo"
        self.con = dbConnection()
    

    def __del__(self):
        self.con.close()
    

    def insertContext(self, context: str):
        query = """
            INSERT INTO {table_name} (context, done)
            VALUES(?, ?)
        """.format(table_name = self.__table_name__)

        self.con.cursor().execute(query, (context, 0, ))
        self.con.commit()


    def updateStatus(self, idx: int, done: int):
        query = """
            UPDATE {table_name}
            SET done = ?
            WHERE todo_idx = ?
        """.format(table_name = self.__table_name__)

        self.con.cursor().execute(query, (done, idx, ))
        self.con.commit()


    def deleteContext(self, idx: int):
        query = """
            DELETE FROM {table_name}
            WHERE todo_idx = ?
        """.format(table_name = self.__table_name__)

        self.con.cursor().execute(query, (idx, ))
        self.con.commit()


    def getTodoList(self):
        query = """
            SELECT * FROM {table_name}
        """.format(table_name = self.__table_name__)

        cur = self.con.cursor()
        cur.execute(query)

        return cur.fetchall()