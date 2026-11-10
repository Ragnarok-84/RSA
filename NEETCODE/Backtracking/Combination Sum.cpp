#include <vector>
using namespace std;
class Solution
{
public:
    vector<vector<int>> res;
    vector<int> cur;

    void backtrack(int start, int target, vector<int> &nums)
    {
        if (target == 0)
        {
            res.push_back(cur);
            return;
        }
        if (target < 0)
            return;

        for (int i = start; i < nums.size(); i++)
        {
            cur.push_back(nums[i]);
            backtrack(i, target - nums[i], nums); // i (không phải i+1)
            cur.pop_back();
        }
    }

    vector<vector<int>> combinationSum(vector<int> &nums, int target)
    {
        backtrack(0, target, nums);
        return res;
    }
};
