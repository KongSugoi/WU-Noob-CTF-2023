# MISC
## 1. Amazing Song Lyrics

### Đề bài

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noob-CTF-2023/main/Picture/misc1_1.png)

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noob-CTF-2023/main/Picture/misc1_2.png)

### Giải quyết 

Nhìn qua ảnh ta biết được đây là loại mật mã ký hiệu dành cho người khiếm thính. Lên mạng và chúng ta sẽ tìm được cách giải mã.

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noob-CTF-2023/main/Picture/misc1_3.png)

`Flag: n00bz{americansignlanguagedecoded}`

## 2. Google Form 1

### Đề bài

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noob-CTF-2023/main/Picture/misc2_1.png)

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noob-CTF-2023/main/Picture/misc2_2.png)

### Giải quyết

Ta thử sử dụng path viewanalytics thì không có giá trị nào trả về. Thử mở source file và tìm kiếm n00bz{ ta thấy được flag 

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc2_3.png)

`Flag: n00bz{1n5p3ct_3l3m3n7_ftw!}`

## 3. Numbers

### Đề bài 

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc3_1.png)

### Giải quyết 

Connect đến server đề bài ta nhận được câu hỏi và cách giải quyết chắc chắn đã được nhắn đến trong đề bài rồi. 

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc3_2.png)

Tìm số lần xuất hiện của chữ số x trong dãy từ 1 đến 1 số bất kỳ, nếu trong dãy số trên xuất hiện 1 số mà xuất hiện nhiều số x thì phải tính tổng số lần xuất hiện của x trong đó luôn. Từ điều kiện đề bài, ta viết 1 đoạn code cơ bản và connect nó với server để xử lí

```
from pwn import *

conn = remote('challs.n00bzunit3d.xyz', 13541)

for e in range(0, 1000):
    c = conn.recvline()
    if b'n00bz{' in c:
        print(c)
        break
    c = conn.recvline()
    if b'n00bz{' in c:
        print(c)
        break
    if (e != 0):
        c = conn.recvline()
        if b'n00bz{' in c:
            print(c)
            break
    data = c.split()
    a = int(data[2].decode("utf-8").split("'")[0])
    b = int(data[5].decode("utf-8").split("?")[0])
    print(a, b)
    t = 500
    while t > 0:
        n, x = b, a
        d = 0
        for j in range(1, n):
            i = j
            while i != 0:
                if i % 10 == x:
                    d += 1
                i //= 10
        t -= 1
    str1 = bytes(str(d), 'UTF-8')
    print(str1)
    # exit()
    conn.send(str1)
    conn.send(b'\n') 
```
`Flag: n00bz{4n_345y_pr0gr4mm1ng_ch4ll}`

## 4. Google Form 2

### Đề bài

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc4_1.png)

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc4_2.png)

### Giải quyết 

Bài này ta lại thử thêm path viewanalytics ở cuối thì thấy ngay flag 

![misc](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/misc4_3.png)

`Flag: n00bz{7h1s_1s_th3_3nd_0f_g00gl3_f0rm5_fl4g_ch3ck3rs}`

# Forensics

## 1. Crack & Crack

### Đề bài 

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for1_1.png)

### Giải quyết 

Bài này muốn ta crack file zip này. Vậy nên ta sử dụng tool tên John The Ripper cùng bộ mật mã Rockyou.txt để crack. 

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for1_2.png)

<p> Nhận được mật khẩu file zip là `1337h4x0r` <p>
<p> Extract file zip ta lại nhận được 1 file pdf có mật khẩu, lại dùng John The Ripper thôi <p>

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for1_3.png)

<p> Nhận được mật khẩu file pdf là `noobmaster` <p>
<p> Mở khóa file pdf và nhận được flag <p>

`Flag: n00bz{CR4CK3D_4ND_CR4CK3D_1a4d2e5f}`

## 2. Avengers

### Đề bài

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for2_1.png)

### Giải quyết

Ta sẽ chạy thật chậm vid và kiểm tra các mã bit được nhận sau đó ghép lại thì ta được 1 đoạn mã như sau: 

`01101110 00110000 00110000 01100010 01111010 01111011 00110111 01101000 00110001 01110011 01011111 00110001 01110011 01011111 00110100 01011111 01110110 00110011 01110010 01111001 01011111 01101100 00110000 01101110 01100111 01011111 01100110 01101100 00110100 01100111 01011111 01110011 00110000 01011111 01110100 01101000 00110100 01110100 01011111 01111001 00110000 01110101 01011111 01100011 00110100 01101110 01101110 00110000 01110100 01011111 01110011 00110000 01101100 01110110 00110011 01011111 00110111 01101000 00110011 01011111 01100011 01101000 00110100 01101100 01101100 00110011 01101110 01100111 00110011 01011111 01101101 00110100 01101110 01110101 00110100 01101100 01101100 01111001 01011111 01100010 00110111 01110111 01011111 00110111 00110011 01110011 00110011 01110010 00110100 01100011 00110111 01011111 00110001 01110011 01011111 00110100 01011111 01110110 00110011 01110010 01111001 01011111 01100111 00110000 00110000 01100100 01011111 01110100 00110000 00110000 01101100 00100001 01111101`

<p> Dịch binary ta nhận được flag  <p>

`Flag: n00bz{7h1s_1s_4_v3ry_l0ng_fl4g_s0_th4t_y0u_c4nn0t_s0lv3_7h3_ch4ll3ng3_m4nu4lly_b7w_73s3r4c7_1s_4_v3ry_g00d_t00l!}`

### 3. QRazy CSV

### Đề bài

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for3_1.png)

### Giải quyết

Vì đề là QR và nhận được file có nhưng vị trí row và col, ta có thể biết được đây là các vị trí để đánh dấu đen cho 1 mã QR, từ đó ta viết 1 đoạn code python
```
from PIL import Image, ImageDraw

secret = open('secret.csv', 'r').read().split('\n')[1:-1]
#cells = {}
#for _ in range(29):
#    cells[_] = []
#
#for _ in secret:
#    a, b = _.split(',')
#    cells[int(a)].append(int(b))

colored = []
for _ in secret:
    a, b = _.split(',')
    colored.append((int(a[1:], 10), int(b[:-1], 10)))

width, height = 2900, 2900
rows, cols = 29, 29
cell_size = width // cols  # Size of each grid cell

image = Image.new("RGB", (width, height), "white")
draw = ImageDraw.Draw(image)

for row in range(rows + 1):
    y = row * cell_size
    draw.line([(0, y), (width, y)], fill="black")  # Horizontal lines

for col in range(cols + 1):
    x = col * cell_size
    draw.line([(x, 0), (x, height)], fill="black")  # Vertical lines

for cell in colored:
    row, col = cell
    x1 = col * cell_size
    y1 = row * cell_size
    x2 = x1 + cell_size
    y2 = y1 + cell_size
    draw.rectangle([(x1, y1), (x2, y2)], fill="black")

image.save("qrcode.png")  # Save the image
image.show()  # Display the image
```

Chạy đoạn code ta nhận được bức ảnh 

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for3_2.png)

<p> Quét mã QR nhận được flag <p>

`Flag: n00bz{qr_c0d3_1n_4_t3xt_f1l3_w0w!!!!!!}`

## 4. Hecked

### Đề bài

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for4_1.png)

### Giải quyết

Đây là 1 file pcap, nên ta mở bằng wireshark, follow TCP và nhận được đoạn giao tiếp giữa 1 client và server

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for4_2.png)

Với dữ kiện đề bài, ta nhận ra `vsFTPd 2.3.4` có thể là Vulnerable Service. Tìm kiếm thử trên google

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for4_3.png)

Vậy là chắc chắn được rồi, giờ chuyển đổi thành md5 thôi

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for4_4.png)

`Flag: n00bz{81b0cd2e46476ef93b51a365629b711b}`

## 5. LSB

### Đề bài

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for5_1.png)

### Giải quyết

Từ đề bài, ta sử dụng tool stegolsb wavsteg để xử lí

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for5_2.png)

`Flag: n00bz{L5B_1n_w4v_f1l3s?!!!}`

## 6. BeepBop

### Đề bài 

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for6_1.png)

### Giải quyết 

Chúng ta sử dụng tool tên QSSTV và Pavucontrol để xử lí

Kết nối với câu lệnh `pactl load-module module-null-sink sink_name=virtual-cable`

Setting:

Ở **Pavucontrol** : chọn **Recording**, chuyển chế độ sang **Monitor of Null output** 

Ở **QSSTV** chọn **Options**, chọn **Configuration** ; Trong bảng **Configuration** chọn phần **Sound**, chuyển **Input và Output Audio Device** thành **pulse -- Pulse Audio Sound Server**  và ấn OK

Chú ý: Ở bảng chọn **QSSTV**, chú ý phần **SSTV** tick vào  **Auto Slant**  và để  **Sensitivity**  ở mode **Auto**

Sau đó chạy câu lệnh `paplay -d virtual-cable chall.wav`

Ta sẽ nhận được bức hình có flag

![for](https://raw.githubusercontent.com/KongSugoi/WU-Noobctf/main/Picture/for6_2.png)

`Flag: n00bz{beep_bop_you_found_me!}`
