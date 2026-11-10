#include <vector>
#include <string>
using namespace std;
class Solution
{
public:
    vector<string> res;

    void backtrack(string cur, int open, int close, int n)
    {
        // If the string is complete
        if (cur.length() == 2 * n)
        {
            res.push_back(cur);
            return;
        }

        // Add '(' if we still can
        if (open < n)
        {
            backtrack(cur + "(", open + 1, close, n);
        }

        // Add ')' if it keeps the string valid
        if (close < open)
        {
            backtrack(cur + ")", open, close + 1, n);
        }
    }

    vector<string> generateParenthesis(int n)
    {
        backtrack("", 0, 0, n);
        return res;
    }
};
