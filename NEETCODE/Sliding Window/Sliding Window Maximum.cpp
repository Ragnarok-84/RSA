#include <vector>
#include <deque>
using namespace std;
class Solution
{
public:
    vector<int> maxSlidingWindow(vector<int> &nums, int k)
    {
        deque<int> dq; // lưu index
        vector<int> result;

        for (int i = 0; i < nums.size(); i++)
        {

            // 1. loại bỏ phần tử ra khỏi window
            if (!dq.empty() && dq.front() <= i - k)
                dq.pop_front();

            // 2. loại bỏ phần tử nhỏ hơn nums[i]
            while (!dq.empty() && nums[dq.back()] < nums[i])
                dq.pop_back();

            // 3. thêm phần tử mới
            dq.push_back(i);

            // 4. ghi kết quả khi window đủ size
            if (i >= k - 1)
                result.push_back(nums[dq.front()]);
        }

        return result;
    }
};
