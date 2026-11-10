#include <vector>
#include <string>
#include <algorithm>
using namespace std;
class Solution
{
public:
    int characterReplacement(string s, int k)
    {
        vector<int> freq(26, 0);
        int l = 0;
        int maxFreq = 0; // tần suất ký tự xuất hiện nhiều nhất trong cửa sổ
        int ans = 0;

        for (int r = 0; r < s.size(); r++)
        {
            freq[s[r] - 'A']++;
            maxFreq = max(maxFreq, freq[s[r] - 'A']);

            // nếu cần thay > k → thu hẹp cửa sổ
            while ((r - l + 1) - maxFreq > k)
            {
                freq[s[l] - 'A']--;
                l++;
            }

            ans = max(ans, r - l + 1);
        }

        return ans;
    }
};
