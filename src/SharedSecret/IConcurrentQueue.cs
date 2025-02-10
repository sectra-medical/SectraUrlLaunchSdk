using System.Collections.Generic;

namespace Sectra.UrlLaunch.SharedSecret;

/// <summary>
/// Implemented by types that provide a thread safe queue. 
/// </summary>
/// <remarks>Implementors must guarante
/// that the implemented methods are thread safe</remarks>
internal interface IConcurrentQueue<T> : IReadOnlyCollection<T> {

    /// <summary>
    /// Must always enqueue an item
    /// </summary>
    /// <param name="item">Item to enqueu</param>
    void Enqueue(T item);

    /// <summary>
    /// Dequeue an item unless the queue is empty
    /// </summary>
    /// <param name="item">Dequeued item or undefined if this method returns false</param>
    /// <returns>false if queue is empty, otherwise true</returns>
    bool TryDequeue(out T? item);

    /// <summary>
    /// Return item at front of queue without dequeueing
    /// </summary>
    /// <param name="item">Item at front of queue or undefined if queue is empty</param>
    /// <returns>false if queue is empty, otherwise true</returns>
    bool TryPeek(out T? item);
}
