#include <vector>
#include <string>
using namespace std;
class Solution
{
public:
    vector<string> res;
    string path;
    vector<string> mp = {
        "", "", "abc", "def",
        "ghi", "jkl", "mno", "pqrs",
        "tuv", "wxyz"};

    void dfs(int idx, string &digits)
    {
        if (idx == digits.size())
        {
            res.push_back(path);
            return;
        }

        string letters = mp[digits[idx] - '0'];
        for (char c : letters)
        {
            path.push_back(c);
            dfs(idx + 1, digits);
            path.pop_back(); // backtrack
        }
    }

    vector<string> letterCombinations(string digits)
    {
        if (digits.empty())
            return {};
        dfs(0, digits);
        return res;
    }
};
