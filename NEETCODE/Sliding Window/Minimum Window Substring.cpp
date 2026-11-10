#include <vector>
#include <string>
#include <climits>
using namespace std;
class Solution
{
public:
    string minWindow(string s, string t)
    {

        // Nếu s ngắn hơn t thì không thể có window hợp lệ
        if (s.size() < t.size())
            return "";

        // need[c]: số lần ký tự c còn THIẾU trong window
        // ban đầu = tần suất ký tự trong t
        vector<int> need(128, 0);
        for (char c : t)
        {
            need[c]++;
        }

        // required: tổng số ký tự còn thiếu để window hợp lệ
        // khi required == 0 → window hiện tại chứa đủ t
        int required = t.size();

        // con trỏ trái của sliding window
        int l = 0;

        // lưu độ dài window nhỏ nhất tìm được
        int minLen = INT_MAX;

        // vị trí bắt đầu của window nhỏ nhất
        int start = 0;

        // mở rộng cửa sổ bằng con trỏ phải r
        for (int r = 0; r < s.size(); r++)
        {

            // nếu ký tự s[r] còn cần (need > 0)
            // → ta đã thỏa mãn thêm 1 ký tự
            if (need[s[r]] > 0)
            {
                required--;
            }

            // trừ đi vì s[r] đã được đưa vào window
            // kể cả khi s[r] không cần (need <= 0)
            need[s[r]]--;

            // khi window hiện tại đã hợp lệ
            // (đã chứa đủ tất cả ký tự của t)
            while (required == 0)
            {

                // cập nhật kết quả nếu window hiện tại nhỏ hơn
                if (r - l + 1 < minLen)
                {
                    minLen = r - l + 1;
                    start = l;
                }

                // chuẩn bị thu hẹp cửa sổ từ bên trái
                need[s[l]]++;

                // nếu sau khi tăng, need > 0
                // → ta vừa làm window thiếu 1 ký tự cần thiết
                if (need[s[l]] > 0)
                {
                    required++;
                }

                // dịch con trỏ trái
                l++;
            }
        }

        // nếu không tìm được window hợp lệ
        return minLen == INT_MAX ? "" : s.substr(start, minLen);
    }
};
