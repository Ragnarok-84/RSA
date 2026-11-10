#include <stack>
#include <string>
using namespace std;
class Solution
{
public:
    bool isValid(string s)
    {
        stack<char> st;
        for (char c : s)
        {
            if (c == '(' || c == '[' || c == '{')
            {
                st.push(c);
            }
            else if (c == ')')
            {
                if (!st.empty())
                {
                    char t = st.top();
                    if (t == '(')
                    {
                        st.pop();
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else if (c == ']')
            {
                if (!st.empty())
                {
                    char t = st.top();
                    if (t == '[')
                    {
                        st.pop();
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else if (c == '}')
            {
                if (!st.empty())
                {
                    char t = st.top();
                    if (t == '{')
                    {
                        st.pop();
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        return st.empty();
    }
};
