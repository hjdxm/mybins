from contextlib import contextmanager
import sqlalchemy
import sqlalchemy.orm
import toml
from copy import deepcopy
from typing_extensions import Annotated
from typing import Union, List, Any, Generator
from datetime import datetime

table_primary_key = Annotated[int,
                              sqlalchemy.orm.mapped_column(primary_key=True)]
requiredAccountString = Annotated[str, sqlalchemy.orm.mapped_column(
    sqlalchemy.String(20), nullable=False)]
notNullInt = Annotated[int, sqlalchemy.orm.mapped_column(nullable=False)]

THE_USER_EXISTS = -1
AN_ILLEGAL_GROUP = -2


class Zxs_sql_user_authentication():

    # Class
    Base = sqlalchemy.orm.declarative_base()
    engine = None
    authentication_default_values = {
        "expired_time": "2030-01-01 00:00:00",
        "date_fmt": "%Y-%m-%d %H:%M:%S",
        "max_login_times": 5,
        "max_error_times": 5,
        "is_deleted": False,
        "group_comment": "Default user group",
        "login_times": 0,
        "error_times": 0,
        "auth_group_id": 1
    }

    class _Authentication_group(Base):
        __tablename__ = "authentication_group"

        auth_group_id: sqlalchemy.orm.Mapped[table_primary_key]
        max_successed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        max_failed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        expired_time: sqlalchemy.orm.Mapped[datetime] = sqlalchemy.orm.mapped_column(
            nullable=False)
        is_deleted: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
            nullable=False)
        group_comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
            sqlalchemy.String(50), nullable=False, index=True, unique=True)

        user_login: sqlalchemy.orm.Mapped[List["Zxs_sql_user_authentication._User_login"]] = sqlalchemy.orm.relationship(
            "_User_login", lazy=True, back_populates="auth_group")

        def __repr__(self):
            return f"auth_group_id:{self.auth_group_id}\tmax_successed_login_times:{self.max_successed_login_times}\tmax_failed_login_times:{self.max_failed_login_times}\texpired_time:{self.expired_time}\tis_deleted:{self.is_deleted}\tgroup_comment:{self.group_comment}\t"

    class _User_login(Base):
        __tablename__ = "user_login"

        user_id: sqlalchemy.orm.Mapped[table_primary_key]
        password: sqlalchemy.orm.Mapped[requiredAccountString]
        nickname: sqlalchemy.orm.Mapped[requiredAccountString]
        successed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        failed_login_times: sqlalchemy.orm.Mapped[notNullInt]
        account: sqlalchemy.orm.Mapped[requiredAccountString] = sqlalchemy.orm.mapped_column(
            unique=True, index=True)
        auth_group_fk: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
            sqlalchemy.ForeignKey("authentication_group.auth_group_id"), nullable=False)

        auth_group: sqlalchemy.orm.Mapped["Zxs_sql_user_authentication._Authentication_group"] = sqlalchemy.orm.relationship(
            "_Authentication_group", lazy=False, back_populates="user_login")

        def __repr__(self):
            return f"user_id:{self.user_id}\tpassword:{self.password}\tnickname:{self.nickname}\tsuccessed_login_times:{self.successed_login_times}\tfailed_login_times:{self.failed_login_times}\taccount:{self.account}\tauth_group_fk:{self.auth_group_fk}"

    # Exception

    class RecordExistsError(Exception):
        def __init__(self, item: Union["Zxs_sql_user_authentication._Authentication_group", "Zxs_sql_user_authentication._User_login"]):
            if isinstance(item, Zxs_sql_user_authentication._Authentication_group):
                info = f"The user group already exists: {item.group_comment}"
            else:
                info = f"The user account already exists: {item.account}"
            super().__init__(info)

    class FailedLoginError(Exception):
        def __init__(self, info: str):
            super().__init__(info)

    # Instance

    def __init__(self, config: Union[str, dict], engine_conf: str):
        '''
        config: 字典或者配置的文件路径
        engine_conf: 配置字典中的 key
        '''
        if isinstance(config, str):
            conf = self.read_config(config)
        else:
            conf = deepcopy(config)
        self.conf = conf
        self._init_engine(**conf[engine_conf])

    def _init_engine(
            self, authentication_default_values: Union[str, None] = None, *args, **kwargs) -> None:
        '''
        连接引擎，并初始化认证数据的默认值
        '''
        self.engine = sqlalchemy.create_engine(*args, **kwargs)
        if authentication_default_values is not None:
            self.authentication_default_values.update(
                self.conf[authentication_default_values])

    def user_group(
            self, group_comment: str, expired_time: datetime = datetime.strptime(authentication_default_values["expired_time"], authentication_default_values["date_fmt"]), max_successed_login_times: int = authentication_default_values["max_login_times"], max_failed_login_times: int = authentication_default_values["max_error_times"], is_deleted: bool = authentication_default_values["is_deleted"]) -> _Authentication_group:
        '''
        group_comment 是必须的
        '''
        return self._Authentication_group(
            expired_time=expired_time,
            max_successed_login_times=max_successed_login_times,
            max_failed_login_times=max_failed_login_times,
            is_deleted=is_deleted,
            group_comment=group_comment
        )

    def user(
        self, account: str, password: str, nickname: str, successed_login_times: int = authentication_default_values["login_times"], failed_login_times: int = authentication_default_values["error_times"], auth_group_fk: int = authentication_default_values["auth_group_id"], auth_group=None
    ) -> _User_login:
        '''
        必须填写 account, password, nickname
        '''
        if auth_group is None:
            person = self._User_login(
                account=account,
                password=password,
                nickname=nickname,
                successed_login_times=successed_login_times,
                failed_login_times=failed_login_times,
                auth_group_fk=auth_group_fk,
            )
        else:
            person = self._User_login(
                account=account,
                password=password,
                nickname=nickname,
                successed_login_times=successed_login_times,
                failed_login_times=failed_login_times,
                auth_group=auth_group,
            )
        return person

    def read_config(self, config: str) -> dict:
        '''
        config:只接受文件路径
        '''
        with open(config, "r", encoding="utf-8") as f:
            return toml.load(f)

    def create_all_table(self) -> bool:
        '''
        创建表，如果表存在，则不做任何事情
        '''
        self.Base.metadata.create_all(self.engine)
        try:
            self.add_group(self.authentication_default_values["group_comment"])
            return True
        except Exception:
            return False

    def add_all_records(self, records: list):
        '''
        records：list[表实例]
        '''
        with sqlalchemy.orm.Session() as Se:
            Se.add_all(records)
            Se.commit()

    def __del__(self):
        '''
        释放 engine 资源
        '''
        if self.engine:
            self.engine.dispose()

    @contextmanager
    def session(self) -> Generator[sqlalchemy.orm.Session, Any, Any]:
        with sqlalchemy.orm.Session(self.engine) as Se:
            yield Se

    def query_group(self, idx_comment: Union[int, str, None] = None) -> List[_Authentication_group]:
        '''
        如果传入 int，那么查找索引
        如果传入 str，那么查找备注
        否则查全表

        return: [_Authentication_group] nullable
        '''
        with self.session() as Se:
            if isinstance(idx_comment, int):
                return Se.query(self._Authentication_group).filter(self._Authentication_group.auth_group_id == idx_comment).all()
            if isinstance(idx_comment, str):
                return Se.query(self._Authentication_group).filter(self._Authentication_group.group_comment == idx_comment).all()
            return Se.query(self._Authentication_group).all()

    def query_user(self, account: Union[str, None] = None, group: Union[int, str, None, _Authentication_group] = None) -> List[_User_login]:
        '''
        IF account is Not None, query the user.
        ELIF group is Not None, query the users in the group.
        ELSE query all users.

        return : [user] nullable
        '''
        with self.session() as Se:
            # query user by accout
            if account is not None:
                return Se.query(self._User_login).filter(self._User_login.account == account).all()
            # query users by group
            elif group is not None:
                if not isinstance(group, self._Authentication_group):
                    temp_group = self.query_group(group)
                    if temp_group:
                        temp_group = temp_group[0]
                else:
                    temp_group = group
                if temp_group:
                    return Se.query(self._User_login).filter(self._User_login.auth_group == temp_group).all()
                else:
                    return []
            else:
                # query all users
                return Se.query(self._User_login).all()

    def add_user(self, account: str, password: str, nickname: str, group: Union[int, str, "Zxs_sql_user_authentication._Authentication_group", None] = authentication_default_values["group_comment"]) -> _User_login:
        '''
        group:先查有没有 group，有则使用，没有则创建，默认使用默认组
        account:检查 account,是否存在，存在则失败

        Return: user which was added.
        '''
        if isinstance(group, int) or isinstance(group, str):
            _group = self.query_group(group)
            if _group:
                _group = _group[0]
            elif isinstance(group, str):
                _group = self.user_group(group_comment=group)
            else:
                raise ValueError(
                    "group must be None, str, int or Zxs_sql_user_authentication._Authentication_group instance.")
        elif isinstance(group, self._Authentication_group):
            _group = group
        else:
            raise ValueError(
                "group must be None, str, int or Zxs_sql_user_authentication._Authentication_group instance.")
        with self.session() as Se:
            person = Se.query(self._User_login).filter(
                self._User_login.account == account).all()
            if person:
                raise Zxs_sql_user_authentication.RecordExistsError(person[0])
            person = self.user(account=account, password=password,
                               nickname=nickname, auth_group=_group)
            Se.add(person)
            Se.commit()
            return person

    def add_group(self, group: _Authentication_group) -> _Authentication_group:
        temp_group = self.query_group(group.group_comment)
        if temp_group:
            raise Zxs_sql_user_authentication.RecordExistsError(temp_group[0])
        self.add_all_records([group])
        return group

    def login(self, account: str, password: str) -> bool:
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
                if user.password != password:
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
                    return True

        return False

    def change_password(self, account: str, password: str) -> Union[_User_login, None]:
        """
        修改用户的密码，并重置登陆错误次数

        return: 成功返回用户对象，失败返回 None
        """
        user = self.query_user(account)
        if user:
            with self.session() as Se:
                user = Se.merge(user[0])
                user.password = password
                user.failed_login_times = 0
                Se.commit()
                return user
        else:
            return None

    def delthis(self):
        with self.session() as Se:
            user = Se.query(self._User_login).where(sqlalchemy.sql.expression.and_(self._User_login.auth_group_fk == 3,self._User_login.successed_login_times == 1)).all()
            if user:
                print(user[0])

if __name__ == "__main__":
    db = Zxs_sql_user_authentication("./sql_zxs.toml", "sqlite")
    db.delthis()
    # print(db.create_all_table())
    # user1 = db.add_user(account="hjdxm", password="1234",
    #                   nickname="呼喊", group="管理员")
    # user2 = db.add_user(account="睿睿", password="1234", nickname="包子")
    # user3 = db.add_user(account="baozi", password="1234", nickname="包子", group="前任")
    # user3 = db.add_user(account="hanghang", password="1234", nickname="包子", group="前任")
    # group = db.query_group("管理员")[0]
    # users = db.query_user(group=group)
    # for user in users:
    #    print(user)
    # db.change_password('baozi', '1234')
    # try:
        # print(db.login("baozi", "1234"))
    # except db.FailedLoginError as e:
        # print(e)
    # user = db.query_user('baozi')[0]
    # print(user)
    # print(user.auth_group)


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
