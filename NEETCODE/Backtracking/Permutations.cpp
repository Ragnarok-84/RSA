#include <vector>
using namespace std;
class Solution
{
public:
    vector<vector<int>> res;
    vector<int> cur;
    vector<bool> visited;
    void backtrack(int k, vector<int> &nums)
    {
        if (k == nums.size())
        {
            res.push_back(cur);
            return;
        }

        for (int i = 0; i < nums.size(); i++)
        {

            if (!visited[i])
            {
                cur.push_back(nums[i]);
                visited[i] = true;
                backtrack(k + 1, nums);
                cur.pop_back();
                visited[i] = false;
            }
        }
    }

    vector<vector<int>> permute(vector<int> &nums)
    {
        for (int i = 0; i < nums.size(); i++)
        {
            visited.push_back(false);
        }
        backtrack(0, nums);
        return res;
    }
};
