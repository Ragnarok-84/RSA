#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    vector<vector<int>> res;
    vector<int> cur;

    void backtrack(int start, vector<int> &nums)
    {
        // mỗi trạng thái đều là 1 subset hợp lệ
        res.push_back(cur);

        for (int i = start; i < nums.size(); i++)
        {
            // bỏ trùng
            if (i > start && nums[i] == nums[i - 1])
                continue;

            cur.push_back(nums[i]);
            backtrack(i + 1, nums);
            cur.pop_back();
        }
    }

    vector<vector<int>> subsetsWithDup(vector<int> &nums)
    {
        sort(nums.begin(), nums.end());
        backtrack(0, nums);
        return res;
    }
};
