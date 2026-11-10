#include <vector>
using namespace std;
class Solution
{
public:
    vector<vector<int>> res;
    vector<int> current;

    void backtrack(int index, vector<int> &nums)
    {
        // mỗi trạng thái hiện tại là 1 subset hợp lệ
        res.push_back(current);

        for (int i = index; i < nums.size(); i++)
        {
            current.push_back(nums[i]); // chọn nums[i]
            backtrack(i + 1, nums);     // đi tiếp
            current.pop_back();         // bỏ chọn (quay lui)
        }
    }

    vector<vector<int>> subsets(vector<int> &nums)
    {
        backtrack(0, nums);
        return res;
    }
};
