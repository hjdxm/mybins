from contextlib import contextmanager
from copy import deepcopy
from typing_extensions import Annotated
from typing import Union, List, Any, Generator, Optional
from datetime import datetime

from passlib.context import CryptContext
import sqlalchemy
import sqlalchemy.orm
import toml

pwc = CryptContext(schemes=['bcrypt'], deprecated="auto")


def verify_password(plain_pw: str, hashed_pw: str) -> bool:
    return pwc.verify(plain_pw, hashed_pw)


def hash_a_pw(plain_pw: str) -> str:
    return pwc.hash(plain_pw)


table_primary_key = Annotated[int, sqlalchemy.orm.mapped_column(primary_key=True)]
requiredAccountString = Annotated[str, sqlalchemy.orm.mapped_column(sqlalchemy.String(20), nullable=False)]
notNullInt = Annotated[int, sqlalchemy.orm.mapped_column(nullable=False)]


class Zxs_sql_user_authentication():

    # Global Variables

    Base = sqlalchemy.orm.declarative_base()
    engine = None

    # Tables

    _User_permission_table = sqlalchemy.Table(
        "user_permission_table",
        Base.metadata,
        sqlalchemy.Column("user_id", sqlalchemy.ForeignKey("user_login.user_id"), primary_key=True),
        sqlalchemy.Column("permission_id", sqlalchemy.ForeignKey("permissions.permission_id"), primary_key=True)
    )
    _User_group_permission_table = sqlalchemy.Table(
        "user_group_permission_table",
        Base.metadata,
        sqlalchemy.Column("auth_group_id", sqlalchemy.ForeignKey("authentication_group.auth_group_id"), primary_key=True),
        sqlalchemy.Column("permission_id", sqlalchemy.ForeignKey("permissions.permission_id"), primary_key=True)
    )

    class _Permission(Base):
        __tablename__ = "permissions"
        permission_id: sqlalchemy.orm.Mapped[table_primary_key]
        permission_name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(sqlalchemy.String(20), nullable=False, index=True, unique=True)
        permission_docu: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(sqlalchemy.String(100))

        allowed_user: sqlalchemy.orm.Mapped[set["Zxs_sql_user_authentication._User_login"]] = sqlalchemy.orm.relationship("_User_login", secondary="user_permission_table", lazy=True, back_populates="user_permission")
        allowed_group: sqlalchemy.orm.Mapped[set["Zxs_sql_user_authentication._Authentication_group"]] = sqlalchemy.orm.relationship("_Authentication_group", secondary="user_group_permission_table", lazy=True, back_populates="group_permission")

        def __repr__(self):
            return f"permission_id:{self.permission_id}\tpermission_name:{self.permission_name}\tpermission_docu:{self.permission_docu}\trelationship:allowed_user, allowed_group"

    class _Authentication_group(Base):
        __tablename__ = "authentication_group"

        auth_group_id: sqlalchemy.orm.Mapped[table_primary_key]
        max_successed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        max_failed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        expired_time: sqlalchemy.orm.Mapped[datetime] = sqlalchemy.orm.mapped_column(nullable=False)
        is_deleted: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(nullable=False)
        group_comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(sqlalchemy.String(50), nullable=False, index=True, unique=True)

        group_permission: sqlalchemy.orm.Mapped[set["Zxs_sql_user_authentication._Permission"]] = sqlalchemy.orm.relationship("_Permission", secondary="user_group_permission_table", lazy=False, back_populates="allowed_group")
        user_login: sqlalchemy.orm.Mapped[List["Zxs_sql_user_authentication._User_login"]] = sqlalchemy.orm.relationship("_User_login", lazy=True, back_populates="auth_group")

        def __repr__(self):
            return f"auth_group_id:{self.auth_group_id}\tmax_successed_login_times:{self.max_successed_login_times}\tmax_failed_login_times:{self.max_failed_login_times}\texpired_time:{self.expired_time}\tis_deleted:{self.is_deleted}\tgroup_comment:{self.group_comment}\tRelationship:group_permission, user_login"

        def to_dict(self):
            temp = {
                "auth_group_id": self.auth_group_id,
                "max_successed_login_times": self.max_successed_login_times,
                "max_failed_login_times": self.max_failed_login_times,
                "expired_time": self.expired_time,
                "is_deleted": self.is_deleted,
                "group_comment": self.group_comment,
                "group_scopes": set([x.permission_name for x in self.group_permission])}
            return temp

    class _User_login(Base):
        __tablename__ = "user_login"

        user_id: sqlalchemy.orm.Mapped[table_primary_key]
        nickname: sqlalchemy.orm.Mapped[requiredAccountString]
        successed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        failed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        hashed_pw: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(sqlalchemy.String(256), nullable=False)
        account: sqlalchemy.orm.Mapped[requiredAccountString] = sqlalchemy.orm.mapped_column(unique=True, index=True)
        auth_group_fk: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(sqlalchemy.ForeignKey("authentication_group.auth_group_id"), nullable=False)

        user_permission: sqlalchemy.orm.Mapped[set["Zxs_sql_user_authentication._Permission"]] = sqlalchemy.orm.relationship("_Permission", secondary="user_permission_table", lazy=False)
        auth_group: sqlalchemy.orm.Mapped["Zxs_sql_user_authentication._Authentication_group"] = sqlalchemy.orm.relationship("_Authentication_group", lazy=False, back_populates="user_login")

        def __repr__(self):
            return f"user_id:{self.user_id}\tpassword:{self.hashed_pw}\tnickname:{self.nickname}\tsuccessed_login_times:{self.successed_login_times}\tfailed_login_times:{self.failed_login_times}\taccount:{self.account}\tauth_group_fk:{self.auth_group_fk}\trelationship: auth_group, user_permission"

        def to_dict(self):
            result = {"user_id": self.user_id,
                      "nickname": self.nickname,
                      "successed_login_times": self.successed_login_times,
                      "failed_login_times": self.failed_login_times,
                      "hashed_pw": self.hashed_pw,
                      "account": self.account,
                      "user_permission": self.user_permission,
                      "auth_group": self.auth_group}
            result.update(self.auth_group.to_dict())
            result["user_scopes"] = set([x.permission_name for x in self.user_permission])
            result["scopes"] = result["user_scopes"].copy()
            result["scopes"].update(result["group_scopes"])
            for key in ["user_permission", "auth_group"]:
                result.pop(key)
            return result

    # Exceptions

    class RecordExistsError(Exception):
        def __init__(self, item: Union["Zxs_sql_user_authentication._Authentication_group", "Zxs_sql_user_authentication._User_login", "Zxs_sql_user_authentication._Permission"]):
            if isinstance(item, Zxs_sql_user_authentication._Authentication_group):
                info = f"The user group already exists: {item.group_comment}"
            else:
                info = f"The user account already exists: {item.account}"
            super().__init__(info)

    class FailedLoginError(Exception):
        def __init__(self, info: str):
            super().__init__(info)

    class RecordNotExistsError(Exception):
        def __init__(self, records: Any):
            super().__init__(f"The record is not exists:{records}")

    # Static methods

    @staticmethod
    def read_config(config: str) -> dict:
        '''
        config:只接受文件路径
        '''
        with open(config, "r", encoding="utf-8") as f:
            return toml.load(f)

    # Instance

    def __init__(self, config: Union[str, dict], engine_conf: str) -> None:
        '''
        config: 字典或者配置的文件路径
        engine_conf: 那个键为 config root
        '''
        if isinstance(config, str):
            conf = self.read_config(config)
        else:
            conf = deepcopy(config)
        self.conf = conf[engine_conf]
        self.engine = sqlalchemy.create_engine(**self.conf["engine"])

    def date_from_str(self, date_string: str, format: Union[None, str] = None) -> datetime:
        """
        将字符串日期转为 datetime

        date_string: 字符串日期
        format: 字符串格式
        """
        _format = format or self.conf["datetemplate"].get("format", "")
        return datetime.strptime(date_string, _format)

    def permission(
            self,
            permission_name: str,
            permission_docu: str = "",) -> _Permission:
        '''
        返回一个 permission 对象
        '''
        return self._Permission(permission_name=permission_name, permission_docu=permission_docu)

    def user_group(
            self,
            group_comment: str,
            expired_time: Optional[datetime] = None,
            max_successed_login_times: Optional[int] = None,
            max_failed_login_times: Optional[int] = None,
            is_deleted: Optional[bool] = None,
            group_permission: Union[List[Union[str, int, "Zxs_sql_user_authentication._Permission"]], None] = None) -> _Authentication_group:
        '''
        group_comment 是必须的
        '''
        args = {"group_comment": group_comment,
                "expired_time": expired_time,
                "max_successed_login_times": max_successed_login_times,
                "max_failed_login_times": max_failed_login_times,
                "is_deleted": is_deleted,
                "group_permission": group_permission}
        # args = locals().copy()
        # args.pop("self")
        temp = self.conf["group"].copy()
        temp.update({k: v for k, v in args.items() if v is not None})
        temp["expired_time"] = self.date_from_str(temp["expired_time"])
        res = set()
        if temp["group_permission"] is not None:
            for key in temp["group_permission"]:
                if isinstance(key, self._Permission):
                    res.add(key)
                else:
                    res.add(self.query_permission(key)[0])
            temp.pop("group_permission")
        temp = self._Authentication_group(** temp)
        if res:
            temp.group_permission.update(res)
        return temp

    def user(
            self,
            account: str,
            password: str,
            nickname: str,
            successed_login_times: Union[int, None] = None,
            failed_login_times: Union[int, None] = None,
            auth_group_fk: Union[int, None] = None,
            auth_group: Union[str, int, None, "Zxs_sql_user_authentication._Authentication_group"] = None,
            user_permission: Union[List[Union[str, int, "Zxs_sql_user_authentication._Permission"]], None] = None) -> _User_login:
        '''
        必须填写 account, password, nickname
        '''
        args = {"account": account,
                "password": password,
                "nickname": nickname,
                "successed_login_times": successed_login_times,
                "failed_login_times": failed_login_times,
                "auth_group_fk": auth_group_fk,
                "auth_group": auth_group,
                "user_permission": user_permission}
        # args = locals().copy()
        # args.pop("self")
        temp = self.conf["user"].copy()
        temp.update({k: v for k, v in args.items() if v is not None})
        if temp["auth_group"] is not None:
            if not isinstance(temp["auth_group"], self._Authentication_group):
                res = self.query_group(temp["auth_group"])
            else:
                res = [temp["auth_group"]]
            temp["auth_group"] = res[0]
        res = set()
        if temp["user_permission"] is not None:
            for key in temp["user_permission"]:
                if not isinstance(key, self._Permission):
                    res.add(self.query_permission(key)[0])
                else:
                    res.add(key)
        temp.pop("user_permission")
        temp["hashed_pw"] = hash_a_pw(temp["password"])
        temp.pop("password")
        temp = self._User_login(**temp)
        if res:
            temp.user_permission.update(res)
        return temp

    def create_all_table(self) -> bool:
        '''
        创建表，如果表存在，则不做任何事情
        '''
        self.Base.metadata.create_all(self.engine)
        try:
            self.add_all_records([self.permission(**self.conf["permission"])])
            self.add_all_records([self.user_group(**self.conf["group"])])
            return True
        except Exception:
            return False

    def add_all_records(self, records: list):
        '''
        records：list[表实例]
        '''
        with self.session() as Se:
            Se.add_all([Se.merge(x) for x in records])
            Se.commit()

    def __del__(self):
        '''
        释放 engine 资源
        '''
        if self.engine:
            self.engine.dispose()

    @contextmanager
    def session(self) -> Generator[sqlalchemy.orm.Session, Any, Any]:
        """
        返回一个会自动释放的 session
        """
        with sqlalchemy.orm.Session(self.engine) as Se:
            yield Se
            Se.expunge_all()

    def query_permission(self, idx_name: Union[int, str, None] = None) -> List[_Permission]:
        '''
        如果传入 int，那么查找索引
        如果传入 str，那么查找name
        如果为 None,那么查全表
        return: [_Permission] nullable
        '''
        with self.session() as Se:
            if isinstance(idx_name, int):
                return Se.query(self._Permission).filter(self._Permission.permission_id == idx_name).all()
            if isinstance(idx_name, str):
                return Se.query(self._Permission).filter(self._Permission.permission_name == idx_name).all()
            if idx_name is None:
                return Se.query(self._Permission).all()

    def query_group(self, idx_comment: Union[int, str, None] = None) -> List[_Authentication_group]:
        '''
        如果传入 int，那么查找索引
        如果传入 str，那么查找备注
        如果是 None， 查全表

        return: [_Authentication_group] nullable
        '''
        with self.session() as Se:
            if isinstance(idx_comment, int):
                return Se.query(self._Authentication_group).filter(self._Authentication_group.auth_group_id == idx_comment).all()
            if isinstance(idx_comment, str):
                return Se.query(self._Authentication_group).filter(self._Authentication_group.group_comment == idx_comment).all()
            if idx_comment is None:
                return Se.query(self._Authentication_group).all()

    def query_user(
            self,
            account: Union[str, None] = None,
            group: Union[int, str, None, _Authentication_group] = None) -> List[_User_login]:
        '''
        如果 accout 不为 None,查个人
        如果 group 不为 None, 查组
        都为 None 查全表

        return : [user] nullable
        '''
        with self.session() as Se:
            # query user by accout
            if account is not None:
                return Se.query(self._User_login).filter(self._User_login.account == account).all()
            # query users by group
            elif group is not None:
                _group = self.query_group(group)
                if _group:
                    return Se.query(self._User_login).filter(self._User_login.auth_group == _group).all()
                else:
                    return []
            else:
                return Se.query(self._User_login).all()

    def login(self, account: str, password: str) -> Union[None, _User_login]:
        """
        对用户登陆，成功后登陆次数 +1，密码错误的话失败登陆 +1

        return: 成功返回 True，失败抛出异常，返回 false 则用户不存在
        """
        user = self.query_user(account)
        if user:
            user = user[0]
            group = user.auth_group
            with self.session() as Se:
                user = Se.merge(user)
                if not verify_password(password, user.hashed_pw):
                    user.failed_login_times += 1
                    Se.commit()
                    raise self.FailedLoginError("登陆密码错误")
                elif group.expired_time <= datetime.now():
                    raise self.FailedLoginError("账户以过期")
                elif group.is_deleted:
                    raise self.FailedLoginError("账户以注销")
                elif group.max_failed_login_times <= user.failed_login_times:
                    raise self.FailedLoginError("密码错误次数过多")
                elif group.max_successed_login_times <= user.successed_login_times:
                    raise self.FailedLoginError("登陆次数达到上限")
                else:
                    user.successed_login_times += 1
                    Se.commit()
                    return user

        return None

    def change_password(self, account: str, password: str) -> Union[_User_login, None]:
        """
        修改用户的密码，并重置登陆错误次数

        return: 成功返回用户对象，失败返回 None
        """
        user = self.query_user(account)
        if user:
            with self.session() as Se:
                user = Se.merge(user[0])
                user.hashed_pw = hash_a_pw(password)
                user.failed_login_times = 0
                Se.commit()
                return user
        else:
            return None


loginDB = Zxs_sql_user_authentication("./sql_zxs.toml", "sqlite")

if __name__ == "__main__":
    print(loginDB.query_user(account=""))
    #    db.create_all_table()
    #    db.add_all_records([
    #        db.user(account="hjdxm", password="1234", nickname="tiger"),
    #        db.user(account="baozi", password="13244", nickname="包子"),
    #        db.user(account="diaoxiao", password="324sckj", nickname="刁校"),
    #        db.user(account="boshi", password="sfhiwoac", nickname="博士"),
    #    ])
#    groups = db.query_group(None)
#    if groups:
#        for group in groups:
#            print(group.to_dict())


'''
class ZXS_SQL():
    def __init__(self, config: str | dict):
        if isinstance(config, str):
            with open(config, "r") as f:
                temp_config = toml.load(f)
        else:
            temp_config = config
        self.config = temp_config


    sqlite_engine = sqlalchemy.create_engine("sqlite:///test_sqlite.db")

    db_meta = sqlalchemy.MetaData()

    user_login = sqlalchemy.Table(
        "user_login", db_meta,
        sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
        sqlalchemy.Column("user_counter", sqlalchemy.String(16),
                          nullable=False, unique=True),
        sqlalchemy.Column("password", sqlalchemy.String(20)),
        sqlalchemy.Column("delete_flag", sqlalchemy.Boolean),
        sqlalchemy.Column("allowed_login", sqlalchemy.Boolean),
        sqlalchemy.Column("allowed_login_times", sqlalchemy.Integer),
        sqlalchemy.Column("allowed_login_datetime", sqlalchemy.DateTime),
        sqlalchemy.Column("allowed_error_password_times", sqlalchemy.Integer),
        sqlalchemy.Column("error_password_times", sqlalchemy.Integer,),
    )

    db_meta.create_all(sqlite_engine)
'''
