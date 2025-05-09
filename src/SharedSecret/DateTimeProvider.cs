using System;

namespace Sectra.UrlLaunch.SharedSecret {
    internal abstract class DateTimeProvider {
        private static DateTimeProvider current = DefaultDateTimeProvider.Instance;

        public static DateTimeProvider Current {
            get => current;

            set {
                if (value == null) {
                    throw new ArgumentNullException("value");
                }
                current = value;
            }
        }

        public abstract DateTime UtcNow { get; }

        public static void ResetToDefault() {
            current = DefaultDateTimeProvider.Instance;
        }
    }

    internal class DefaultDateTimeProvider : DateTimeProvider {
        public static DefaultDateTimeProvider Instance { get; } = new DefaultDateTimeProvider();
        public override DateTime UtcNow => DateTime.UtcNow;
    }
}
