# First Lesson: `House-of-force`
>Glibc ver: 2.28
Trong bài viết này, mình sẽ giải thích những vấn đề bao gồm:

- Fastbins(2.28) check những gì?

- Bug ở đâu?

- Làm sao để ta chuyển bug đó thành 1 primitive arbitary write?

- Nếu như chúng ta đã có 1 primitive mạnh, ta nên ghi đè giá trị quan trọng nào để `drop the shell`?

### Fastbins(2.28) check những gì?



### Bug Class - Heap OverFlow

- Nếu như ta claim size chúng ta nhập vào nhỏ hơn so với input của chúng ta nhập vào, chúng ta nhận thấy input của ta đã ghi đè vào những giá trị quan trọng trong chương trình... Và một trong những giá trị quan trọng nhất trong heap layout chính là top chunk, hay chính là phần vùng nhớ còn lại mà heap chưa sử dụng. Vì vậy, nếu ta ghi đè vào giá trị này, ta có thể khiến chương trình "hiểu nhầm rằng vùng nhớ heap rất lớn" dẫn tới `malloc` có thể ghi đè lên những segment quan trọng khác.

### Primitive Discovery

- Vậy làm sao từ bug này, ta có thể chuyển nó thành 1 primitive mạnh?

- Tạm bỏ qua việc khai thác lỗ hổng, ta tập trung vào việc chứng minh rằng bug này có thể thực hiện được arbitary write và thử sử dụng nó để ghi đè giá trị `target` ở `0x602010`

- Đầu tiên, ta ghi đè top chunk bằng 1 giá trị cực lớn(ví dụ 0xffffffffffffffff):
 Từ đây, ta có thể khiến chương trình nghĩ rằng heap chiếm 1 bộ nhớ rất lớn, từ đó ta có thể ghi đè bất kỳ địa chỉ nào, kể cả những địa chỉ quan trọng:

- Nhưng địa chỉ của heap là `0x603000` trong khi địa chỉ của target là `602010`, vậy làm sao 1 buffer ở địa chỉ cao hơn có thể ghi đè được địa chỉ thấp hơn?

Ta có công thức:
def delta(x, y):
    return (0xffffffffffffffff - x) + y
### Exploitation



