using System;
using System.Diagnostics;

namespace Multi_Layer_Spoofing_Detector
{
    public static class DockerChecker
    {
        public static bool IsDockerInstalled(out string error)
        {
            return RunCommand("docker", "--version", out error);
        }

        public static bool IsDockerRunning(out string error)
        {
            return RunCommand("docker", "info", out error);
        }

        public static bool IsDockerImageAvailable(string imageName, out string error)
        {
            error = "";

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "docker",
                        Arguments = $"image inspect {imageName}",
                        RedirectStandardError = true,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    error = $"Docker image '{imageName}' not found.";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }


        public static bool IsCICFlowMeterImageAvailable(out string error)
        {
            return RunCommand("docker", "image inspect cicflowmeter", out error);
        }

        private static bool RunCommand(string fileName, string arguments, out string error)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = fileName,
                        Arguments = arguments,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit(5000);

                error = process.ExitCode == 0 ? "" : process.StandardError.ReadToEnd();
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }
}
