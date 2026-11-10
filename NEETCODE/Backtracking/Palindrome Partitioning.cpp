#include <vector>
#include <string>
using namespace std;
class Solution
{
public:
    vector<vector<string>> res;
    vector<string> path;
    string s;

    bool isPalindrome(int l, int r)
    {
        while (l < r)
        {
            if (s[l++] != s[r--])
                return false;
        }
        return true;
    }

    void dfs(int start)
    {
        if (start == s.size())
        {
            res.push_back(path);
            return;
        }

        for (int end = start; end < s.size(); end++)
        {
            if (isPalindrome(start, end))
            {
                path.push_back(s.substr(start, end - start + 1));
                dfs(end + 1);
                path.pop_back(); // backtrack
            }
        }
    }

    vector<vector<string>> partition(string str)
    {
        s = str;
        dfs(0);
        return res;
    }
};
