#include <vector>
#include <algorithm>
using namespace std;
class Solution
{
public:
    vector<vector<int>> res;
    vector<int> cur;

    void backtrack(int start, int target, vector<int> &candidates)
    {
        if (target == 0)
        {
            res.push_back(cur);
            return;
        }

        for (int i = start; i < candidates.size(); i++)
        {

            //  skip duplicate ở cùng tầng
            if (i > start && candidates[i] == candidates[i - 1])
                continue;

            if (candidates[i] > target)
                break;

            cur.push_back(candidates[i]);
            backtrack(i + 1, target - candidates[i], candidates); // i + 1
            cur.pop_back();
        }
    }

    vector<vector<int>> combinationSum2(vector<int> &candidates, int target)
    {
        sort(candidates.begin(), candidates.end());
        backtrack(0, target, candidates);
        return res;
    }
};
